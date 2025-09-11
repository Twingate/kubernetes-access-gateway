// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package wsproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"bytes"
	"context"

	"github.com/jonboulle/clockwork"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

var (
	errFailedToConvertJSON = errors.New("failed to convert json")
	errFailedToWriteEvent  = errors.New("failed to write recording")
	errAlreadyFinished     = errors.New("recording already finished")
)

var (
	recordedSessionDuration prometheus.Histogram
)

func RegisterRecordedSessionMetrics(namespace string, registry *prometheus.Registry) {
	recordedSessionDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "recorded_session_duration_seconds",
		Help:      "Duration of WebSocket session in seconds",
		Buckets:   []float64{1, 5, 10, 30, 60, 300, 600, 1800, 3600},
	})
	registry.MustRegister(recordedSessionDuration)
}

type resizeMsg struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

type K8sMetadata struct {
	PodName   string `json:"podname"`
	Namespace string `json:"namespace"`
	Container string `json:"container"`
}

type AsciicastHeader struct {
	Version     int          `json:"version"`
	Width       int          `json:"width"`
	Height      int          `json:"height"`
	Timestamp   int64        `json:"timestamp"`
	Command     string       `json:"command,omitempty"`
	User        string       `json:"user"`
	K8sMetadata *K8sMetadata `json:"kubernetes,omitempty"`
}

type Recorder interface {
	WriteHeader(h AsciicastHeader) error
	WriteOutputEvent(data []byte) error
	WriteResizeEvent(width int, height int) error
	IsHeaderWritten() bool
	Stop()
}

type config struct {
	// Logger to use for logging
	logger *zap.Logger

	// Clock to use for time
	clock clockwork.Clock

	// Threshold (in bytes) of the recorded lines to flush.
	// If 0, no threshold is used.
	flushSizeThreshold int

	// Interval to flush
	// If 0, no periodic flush is used.
	flushInterval time.Duration
}

type AsciicastRecorder struct {
	config config

	start         time.Time
	header        string
	recordedLines []string

	// number of flushes
	flushCount int
	// ticker for periodic flush
	flushTicker clockwork.Ticker
	// channel to signal that a flush is needed
	flushCh chan struct{}
	// wait group for flush goroutine
	flushWg sync.WaitGroup
	// whether the recorder is stopped
	stopped bool

	mu sync.Mutex
}

func NewRecorder(logger *zap.Logger, opts ...RecorderOption) *AsciicastRecorder {
	r := &AsciicastRecorder{
		start:         time.Now(),
		recordedLines: []string{},
		config: config{
			logger: logger,
			clock:  clockwork.NewRealClock(),
		},
		flushCount: 0,
		flushCh:    make(chan struct{}, 1),
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.config.flushInterval > 0 {
		r.flushTicker = r.config.clock.NewTicker(r.config.flushInterval)
	}

	r.flushWg.Add(1)

	go r.flushLoop()

	return r
}

type RecorderOption func(*AsciicastRecorder)

func WithFlushSizeThreshold(limit int) RecorderOption {
	return func(r *AsciicastRecorder) {
		r.config.flushSizeThreshold = limit
	}
}

func WithFlushInterval(interval time.Duration) RecorderOption {
	return func(r *AsciicastRecorder) {
		r.config.flushInterval = interval
	}
}

func WithClock(clock clockwork.Clock) RecorderOption {
	return func(r *AsciicastRecorder) {
		r.config.clock = clock
	}
}

func (r *AsciicastRecorder) WriteHeader(h AsciicastHeader) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	jsonEvent, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("%w: %w", errFailedToConvertJSON, err)
	}

	r.header = string(jsonEvent)

	return nil
}

func (r *AsciicastRecorder) WriteOutputEvent(data []byte) error {
	return r.writeJSON([]any{
		time.Since(r.start).Seconds(),
		"o",
		string(data)})
}

func (r *AsciicastRecorder) WriteResizeEvent(width int, height int) (err error) {
	return r.writeJSON([]any{
		time.Since(r.start).Seconds(),
		"r",
		fmt.Sprintf("%dx%d", width, height)})
}

func (r *AsciicastRecorder) IsHeaderWritten() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.header != ""
}

func (r *AsciicastRecorder) Stop() {
	r.mu.Lock()

	if r.stopped {
		r.mu.Unlock()

		return
	}

	r.stopped = true
	duration := time.Since(r.start).Seconds()
	r.mu.Unlock()

	recordedSessionDuration.Observe(duration)

	// Signal stop and wait for flush goroutine to finish
	close(r.flushCh)
	r.flushWg.Wait()

	// Do a final flush to ensure we have a finish audit log
	r.flush(true)
}

func (r *AsciicastRecorder) writeJSON(data any) error {
	jsonEvent, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("%w: %w", errFailedToConvertJSON, err)
	}

	if err := r.storeEvent(string(jsonEvent)); err != nil {
		return fmt.Errorf("%w: %w", errFailedToWriteEvent, err)
	}

	return nil
}

func (r *AsciicastRecorder) storeEvent(event string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.stopped {
		return errAlreadyFinished
	}

	r.recordedLines = append(r.recordedLines, event)
	totalSize := 0

	for _, line := range r.recordedLines {
		totalSize += len(line)
	}

	if r.config.flushSizeThreshold > 0 && totalSize >= r.config.flushSizeThreshold {
		// Send a flush signal if there is no pending flush
		select {
		case r.flushCh <- struct{}{}:
		default:
		}
	}

	return nil
}

func (r *AsciicastRecorder) flushLoop() {
	defer r.flushWg.Done()

	if r.flushTicker != nil {
		defer r.flushTicker.Stop()
	}

	var tickerCh <-chan time.Time
	if r.flushTicker != nil {
		tickerCh = r.flushTicker.Chan()
	}

	for {
		select {
		case <-tickerCh: // if no periodic, nil channel blocks forever
			r.flush(false)
		case _, ok := <-r.flushCh:
			if !ok {
				return
			}

			r.flush(false)
		}
	}
}

func (r *AsciicastRecorder) flush(isFinal bool) {
	r.mu.Lock()

	// Always flush final logs. Otherwise, flush if there is a header and some events.
	shouldFlush := isFinal || (len(r.recordedLines) > 0 && r.header != "")
	if !shouldFlush {
		r.mu.Unlock()
		return
	}

	var message string
	if isFinal {
		message = "session finished"
	} else {
		message = "session recording"
	}

	// Prepare log payload while holding the lock, then release before network call.
	r.flushCount++
	seq := r.flushCount
	asciicast := strings.Join(append([]string{r.header}, r.recordedLines...), "\n")
	// reset buffer
	r.recordedLines = r.recordedLines[:0]
	r.mu.Unlock()

    // Optionally enrich with an AI summary (best-effort, time-limited).
    // Only include the field if a non-empty summary is returned.
    ai := summarizeAsciicastWithOpenAI(asciicast)

    fields := []zap.Field{
        zap.String("asciicast", asciicast),
        zap.Int("asciicast_sequence_num", seq),
    }
    if ai != "" {
        fields = append(fields, zap.String("ai", ai))
    }

    r.config.logger.Info(message, fields...)
}

// summarizeAsciicastWithOpenAI sends a short prompt to OpenAI to obtain
// a compact, plain-text summary of the asciicast for audit logging.
// Behavior:
// - Off by default. Enable by setting env GATEWAY_AI_SUMMARY_ENABLED to "1" or "true".
// - Requires OPENAI_API_KEY. Model can be overridden via OPENAI_MODEL (default: gpt-4o-mini).
// - Hard time limit and best-effort; returns empty string on any error.
func summarizeAsciicastWithOpenAI(asciicast string) string {
	enabled := os.Getenv("GATEWAY_AI_SUMMARY_ENABLED")
	if enabled != "1" && strings.ToLower(enabled) != "true" {
		return ""
	}

	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		return ""
	}

	model := os.Getenv("OPENAI_MODEL")
	if model == "" {
		model = "gpt-4o-mini"
	}

	// To keep requests small, trim very long sessions.
	const maxChars = 8000
	if len(asciicast) > maxChars {
		asciicast = asciicast[:maxChars]
	}

	system_prompt := os.Getenv("AI_SYSTEM_PROMPT")
	if system_prompt == "" {
		system_prompt = "You are a Senior Security Engineer. Output should be in JSON format and contain 2 fields only: 'summary' and 'score'."
	}

	user_prompt := os.Getenv("AI_USER_PROMPT")
	if user_prompt == "" {
		user_prompt = "Summarize the following remote shell session and provide a brief description of it in <= 20 words. Also provide a security score between 1 and 5 where 5 is a major security risk and 1 is no risk. The session: "
	}
	user_prompt = strings.Join([]string{user_prompt, asciicast}, "")

	// Chat Completions payload
	payload := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": system_prompt},
			{"role": "user", "content": user_prompt},
		},
		"max_tokens":  64,
		"temperature": 0.2,
	}

	b, _ := json.Marshal(payload)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.openai.com/v1/chat/completions", bytes.NewReader(b))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return ""
	}

	if len(parsed.Choices) == 0 {
		return ""
	}

	return strings.TrimSpace(parsed.Choices[0].Message.Content)
}
