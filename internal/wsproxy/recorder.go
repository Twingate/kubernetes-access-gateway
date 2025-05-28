package wsproxy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

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
	start         time.Time
	state         State
	recordedLines []string
}

func NewRecorder() *AsciinemaRecorder {
	return &AsciinemaRecorder{
		start:         time.Now(),
		recordedLines: []string{},
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
	logger := zap.S()
	recordingData := strings.Join(r.recordedLines, "\n")

	logger.Info(recordingData)

	encoded := base64.URLEncoding.EncodeToString([]byte(recordingData))

	// Chrome supports up to 2MB. 100_000 is a conservative truncation
	if len(encoded) < 100_000 {
		asciinemaURL := "https://www.twingate.com/asciinema?q=" + encoded

		logger.Info("View this asciinema cast at: " + asciinemaURL)
	}

	r.state = FinishedState
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

	// TODO: do we want to cap or truncate this at some point?
	r.recordedLines = append(r.recordedLines, event)

	return nil
}
