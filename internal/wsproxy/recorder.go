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
	// If 0, never flush periodically.
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
	// signal that the recorder is stopped
	stopped chan struct{}

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
		stopped:    make(chan struct{}),
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.config.flushInterval > 0 {
		r.flushTicker = r.config.clock.NewTicker(r.config.flushInterval)
		go r.periodicFlush()
	}

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
	defer r.mu.Unlock()

	select {
	case <-r.stopped:
		return
	default:
		close(r.stopped)
	}

	if r.flushTicker != nil {
		r.flushTicker.Stop()
	}

	r.flushLocked(true)
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

	select {
	case <-r.stopped:
		return errAlreadyFinished
	default:
	}

	r.recordedLines = append(r.recordedLines, event)
	totalSize := 0

	for _, line := range r.recordedLines {
		totalSize += len(line)
	}

	if r.config.flushSizeThreshold > 0 && totalSize >= r.config.flushSizeThreshold {
		r.flushLocked(false)
	}

	return nil
}

func (r *AsciinemaRecorder) periodicFlush() {
	for {
		select {
		case <-r.flushTicker.Chan():
			r.mu.Lock()
			select {
			case <-r.stopped:
				r.mu.Unlock()
				return
			default:
				r.flushLocked(false)
				r.mu.Unlock()
			}
		case <-r.stopped:
			return
		}
	}
}

// flushLocked flushes the recorded lines to the logger and reset the recorded lines.
// Caller must hold the lock.
func (r *AsciinemaRecorder) flushLocked(sessionFinished bool) {
	if !sessionFinished && len(r.recordedLines) == 0 {
		return
	}

	var message string
	if sessionFinished {
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
