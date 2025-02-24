package wsproxy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecorder_NewRecorder(t *testing.T) {
	r := NewRecorder()
	assert.NotNil(t, r, "NewRecorder should return a non-nil recording")
}

func TestRecorder_WriteOutputEvent(t *testing.T) {
	r := NewRecorder()

	err := r.WriteOutputEvent([]byte("test output"))
	require.NoError(t, err, "WriteOutputEvent should not return an error")

	assert.Len(t, r.recordedLines, 1, "Recorder should have one event")

	var event []any
	err = json.Unmarshal([]byte(r.recordedLines[0]), &event)
	require.NoError(t, err, "Event should be valid JSON")
	require.Len(t, event, 3, "Event should have three elements")

	// First element is time (float)
	_, ok := event[0].(float64)
	assert.True(t, ok, "First element should be a float (time)")

	// Second element is event type
	assert.Equal(t, "o", event[1], "Second element should be 'o' (output event)")

	// Third element is the data
	assert.Equal(t, "test output", event[2], "Third element should be the output data")
}

func TestRecorder_WriteResizeEvent(t *testing.T) {
	r := NewRecorder()

	err := r.WriteResizeEvent(80, 24)
	require.NoError(t, err, "WriteResizeEvent should not return an error")

	assert.Len(t, r.recordedLines, 1, "Recorder should have one event")

	var event []any
	err = json.Unmarshal([]byte(r.recordedLines[0]), &event)
	require.NoError(t, err, "Event should be valid JSON")
	require.Len(t, event, 3, "Event should have three elements")

	// First element is time (float)
	_, ok := event[0].(float64)
	assert.True(t, ok, "First element should be a float (time)")

	// Second element is event type
	assert.Equal(t, "r", event[1], "Second element should be 'r' (resize event)")

	// Third element is the size
	assert.Equal(t, "80x24", event[2], "Third element should be the size")
}

func TestRecorder_WriteHeader(t *testing.T) {
	r := NewRecorder()

	header := asciinemaHeader{
		Version:   2,
		Width:     80,
		Height:    24,
		Timestamp: time.Now().Unix(),
		Command:   "/bin/bash",
		Env:       map[string]string{"TERM": "xterm-256color"},
		User:      "testuser",
		K8sMetadata: &k8sMetadata{
			PodName:   "test-pod",
			Namespace: "default",
			Container: "main",
		},
	}

	err := r.WriteHeader(header)
	require.NoError(t, err, "WriteHeader should not return an error")

	assert.Len(t, r.recordedLines, 1, "Recorder should have one event")

	var recordedHeader asciinemaHeader
	err = json.Unmarshal([]byte(r.recordedLines[0]), &recordedHeader)
	require.NoError(t, err, "Header should be valid JSON")
	assert.Equal(t, header, recordedHeader)
}

func TestRecorder_MultipleEvents(t *testing.T) {
	r := NewRecorder()

	header := asciinemaHeader{
		Version: 2,
		Width:   80,
		Height:  24,
	}

	// Write multiple events
	require.NoError(t, r.WriteHeader(header))
	require.NoError(t, r.WriteOutputEvent([]byte("first output")))
	require.NoError(t, r.WriteResizeEvent(100, 30))
	require.NoError(t, r.WriteOutputEvent([]byte("second output")))

	assert.Len(t, r.recordedLines, 4, "Recorder should have four events")

	// Validate header
	var recordedHeader asciinemaHeader
	err := json.Unmarshal([]byte(r.recordedLines[0]), &recordedHeader)
	require.NoError(t, err)
	assert.Equal(t, header.Version, recordedHeader.Version)

	// Validate second output event
	var lastEvent []any
	err = json.Unmarshal([]byte(r.recordedLines[3]), &lastEvent)
	require.NoError(t, err)
	assert.Equal(t, "o", lastEvent[1])
	assert.Equal(t, "second output", lastEvent[2])
}

func TestRecorder_StoreEventAfterStop(t *testing.T) {
	r := NewRecorder()

	// Write an event
	require.NoError(t, r.WriteOutputEvent([]byte("test")))

	// Capture r.recordedLines before Stop
	recordingLength := len(r.recordedLines)
	assert.Equal(t, 1, recordingLength, "Recorder should have one event before Stop")

	// Stop the recording
	r.Stop()

	// Try to write after stop
	err := r.WriteOutputEvent([]byte("should fail"))
	require.Error(t, err, "Writing after stop should return an error")
	assert.Contains(t, err.Error(), "recording already finished")

	// Check that nothing was added
	assert.Len(t, r.recordedLines, recordingLength, "Recording length should not change after Stop")
}

func TestRecorderFlow(t *testing.T) {
	r := NewRecorder()

	// Verify start time is recent
	assert.WithinDuration(t, time.Now(), r.start, 1*time.Second, "Recorder start time should be recent")

	// Write header
	header := asciinemaHeader{
		Version: 2,
		Width:   80,
		Height:  24,
	}
	require.NoError(t, r.WriteHeader(header))

	// Check state flag after writing header
	assert.Equal(t, StartedState, r.state, "state should be StartedState after WriteHeader")

	// Write some events
	require.NoError(t, r.WriteOutputEvent([]byte("output 1")))
	time.Sleep(10 * time.Millisecond) // Sleep to ensure time difference
	require.NoError(t, r.WriteResizeEvent(90, 30))
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, r.WriteOutputEvent([]byte("output 2")))

	assert.Len(t, r.recordedLines, 4, "Recorder should have four events")

	// Verify timing order is correct
	var event1, event2, event3 []any

	require.NoError(t, json.Unmarshal([]byte(r.recordedLines[1]), &event1))
	require.NoError(t, json.Unmarshal([]byte(r.recordedLines[2]), &event2))
	require.NoError(t, json.Unmarshal([]byte(r.recordedLines[3]), &event3))

	time1 := event1[0].(float64)
	time2 := event2[0].(float64)
	time3 := event3[0].(float64)

	assert.Less(t, time1, time2, "Events should have increasing timestamps")
	assert.Less(t, time2, time3, "Events should have increasing timestamps")

	// Check state before stopping
	assert.Equal(t, StartedState, r.state, "state should be Started before Stop")

	// Stop the recording
	r.Stop()

	// Check state after stopping
	assert.Equal(t, FinishedState, r.state, "state should be Finished after Stop")
}

func TestK8sMetadata(t *testing.T) {
	metadata := k8sMetadata{
		PodName:   "test-pod",
		Namespace: "test-namespace",
		Container: "test-container",
	}

	assert.Equal(t, "test-pod", metadata.PodName)
	assert.Equal(t, "test-namespace", metadata.Namespace)
	assert.Equal(t, "test-container", metadata.Container)
}

func TestRecorder_WriteJSON_Error(t *testing.T) {
	r := NewRecorder()

	// Create a value that cannot be marshaled to JSON, a function
	badValue := struct {
		F func()
	}{
		F: func() {},
	}

	// This should return an error
	err := r.writeJSON(badValue)
	require.Error(t, err, "writeJSON should return error for unmarshallable value")
	assert.Contains(t, err.Error(), "failed to convert json")
}

func TestRecorder_StoreEvent_Error(t *testing.T) {
	r := NewRecorder()
	r.state = FinishedState

	err := r.storeEvent("test event")
	require.Error(t, err, "storeEvent should return error when recording is finished")
	assert.Equal(t, errAlreadyFinished, err)
}
