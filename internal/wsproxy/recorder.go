package wsproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
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
	IsStarted() bool
	Stop()
}

type State int

const (
	NoneState State = iota
	StartedState
	FinishedState
)

type AsciinemaRecorder struct {
	logger        *zap.Logger
	start         time.Time
	state         State
	recordedLines []string
	// total size (in bytes) of the recorded lines
	totalSize int
	// threshold (in bytes) of the recorded lines to flush
	flushSizeThreshold int
	// interval to flush
	flushInterval time.Duration
	// number of flushes
	flushCount int
	// ticker for periodic flush
	flushTicker clockwork.Ticker
	// signal that the recorder is stopped
	stopped chan struct{}

	// clock for testing
	clock clockwork.Clock

	mu sync.Mutex
}

func NewRecorder(logger *zap.Logger, opts ...RecorderOption) *AsciinemaRecorder {
	r := &AsciinemaRecorder{
		logger:             logger,
		start:              time.Now(),
		recordedLines:      []string{},
		totalSize:          0,
		flushSizeThreshold: 64000,
		flushCount:         0,
		flushInterval:      time.Minute,
		stopped:            make(chan struct{}),
		clock:              clockwork.NewRealClock(),
	}

	for _, opt := range opts {
		opt(r)
	}

	r.flushTicker = r.clock.NewTicker(r.flushInterval)
	go r.periodicFlush()

	return r
}

type RecorderOption func(*AsciinemaRecorder)

func WithFlushSizeThreshold(limit int) RecorderOption {
	return func(r *AsciinemaRecorder) {
		r.flushSizeThreshold = limit
	}
}

func WithFlushInterval(interval time.Duration) RecorderOption {
	return func(r *AsciinemaRecorder) {
		r.flushInterval = interval
	}
}

func WithClock(clock clockwork.Clock) RecorderOption {
	return func(r *AsciinemaRecorder) {
		r.clock = clock
	}
}

func (r *AsciinemaRecorder) WriteHeader(h asciinemaHeader) error {
	r.state = StartedState

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

func (r *AsciinemaRecorder) IsStarted() bool {
	return r.state == StartedState
}

func (r *AsciinemaRecorder) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.flushTicker.Stop()
	close(r.stopped)

	r.state = FinishedState
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
	if r.state == FinishedState {
		return errAlreadyFinished
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.recordedLines = append(r.recordedLines, event)
	r.totalSize += len(event)

	if r.totalSize >= r.flushSizeThreshold {
		r.flushLocked(false)
	}

	return nil
}

func (r *AsciinemaRecorder) periodicFlush() {
	for {
		select {
		case <-r.flushTicker.Chan():
			r.mu.Lock()
			r.flushLocked(false)
			r.mu.Unlock()
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
	r.logger.Info(message,
		zap.String("asciinema_data", strings.Join(r.recordedLines, "\n")),
		zap.Int("asciinema_sequence_num", r.flushCount),
	)

	r.recordedLines = r.recordedLines[:0]
	r.totalSize = 0
}
