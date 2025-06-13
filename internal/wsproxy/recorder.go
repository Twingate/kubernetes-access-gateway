package wsproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jonboulle/clockwork"
	"go.uber.org/zap"
)

var (
	errFailedToConvertJSON = errors.New("failed to convert json")
	errFailedToWriteEvent  = errors.New("failed to write recording")
	errAlreadyFinished     = errors.New("recording already finished")
)

type resizeMsg struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

type k8sMetadata struct {
	PodName   string `json:"podname"`
	Namespace string `json:"namespace"`
	Container string `json:"container"`
}

type asciinemaHeader struct {
	Version     int               `json:"version"`
	Width       int               `json:"width"`
	Height      int               `json:"height"`
	Timestamp   int64             `json:"timestamp"`
	Command     string            `json:"command,omitempty"`
	Env         map[string]string `json:"env"`
	User        string            `json:"user"`
	K8sMetadata *k8sMetadata      `json:"kubernetes,omitempty"`
}

type Recorder interface {
	WriteHeader(h asciinemaHeader) error
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

type AsciinemaRecorder struct {
	config config

	start         time.Time
	headerWritten atomic.Bool
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

func NewRecorder(logger *zap.Logger, opts ...RecorderOption) *AsciinemaRecorder {
	r := &AsciinemaRecorder{
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

type RecorderOption func(*AsciinemaRecorder)

func WithFlushSizeThreshold(limit int) RecorderOption {
	return func(r *AsciinemaRecorder) {
		r.config.flushSizeThreshold = limit
	}
}

func WithFlushInterval(interval time.Duration) RecorderOption {
	return func(r *AsciinemaRecorder) {
		r.config.flushInterval = interval
	}
}

func WithClock(clock clockwork.Clock) RecorderOption {
	return func(r *AsciinemaRecorder) {
		r.config.clock = clock
	}
}

func (r *AsciinemaRecorder) WriteHeader(h asciinemaHeader) error {
	r.headerWritten.Store(true)

	return r.writeJSON(h)
}

func (r *AsciinemaRecorder) WriteOutputEvent(data []byte) error {
	return r.writeJSON([]any{
		time.Since(r.start).Seconds(),
		"o",
		string(data)})
}

func (r *AsciinemaRecorder) WriteResizeEvent(width int, height int) (err error) {
	return r.writeJSON([]any{
		time.Since(r.start).Seconds(),
		"r",
		fmt.Sprintf("%dx%d", width, height)})
}

func (r *AsciinemaRecorder) IsHeaderWritten() bool {
	return r.headerWritten.Load()
}

func (r *AsciinemaRecorder) Stop() {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()

		return
	}

	r.stopped = true
	r.mu.Unlock()

	// Signal stop and wait for flush goroutine to finish
	close(r.flushCh)
	r.flushWg.Wait()

	// Do a final flush to ensure we have a finish audit log
	r.flush(true)
}

func (r *AsciinemaRecorder) writeJSON(data any) error {
	jsonEvent, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("%w: %w", errFailedToConvertJSON, err)
	}

	if err := r.storeEvent(string(jsonEvent)); err != nil {
		return fmt.Errorf("%w: %w", errFailedToWriteEvent, err)
	}

	return nil
}

func (r *AsciinemaRecorder) storeEvent(event string) error {
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

func (r *AsciinemaRecorder) flushLoop() {
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

func (r *AsciinemaRecorder) flush(isFinal bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !isFinal && len(r.recordedLines) == 0 {
		return
	}

	var message string
	if isFinal {
		message = "session finished"
	} else {
		message = "session recording"
	}

	r.flushCount++
	r.config.logger.Info(message,
		zap.String("asciinema_data", strings.Join(r.recordedLines, "\n")),
		zap.Int("asciinema_sequence_num", r.flushCount),
	)

	r.recordedLines = r.recordedLines[:0]
}
