// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"bytes"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"k8sgateway/internal/sessionrecorder"
)

// Mock implementations

type mockRecorder struct {
	mock.Mock

	headers      []sessionrecorder.AsciicastHeader
	outputEvents [][]byte
	resizeEvents []sessionrecorder.ResizeMsg
}

func (m *mockRecorder) WriteHeader(h sessionrecorder.AsciicastHeader) error {
	m.headers = append(m.headers, h)
	args := m.Called(h)

	return args.Error(0)
}

func (m *mockRecorder) WriteOutputEvent(data []byte) error {
	m.outputEvents = append(m.outputEvents, data)
	args := m.Called(data)

	return args.Error(0)
}

func (m *mockRecorder) WriteResizeEvent(width int, height int) error {
	m.resizeEvents = append(m.resizeEvents, sessionrecorder.ResizeMsg{Width: width, Height: height})
	args := m.Called(width, height)

	return args.Error(0)
}

func (m *mockRecorder) Stop() {
	m.Called()
}

func (m *mockRecorder) IsHeaderWritten() bool {
	return len(m.headers) > 0
}

type mockSessionRecorderFactory struct {
	mock.Mock
}

func (m *mockSessionRecorderFactory) NewRecorder(logger *zap.Logger) sessionrecorder.Recorder {
	args := m.Called(logger)

	return args.Get(0).(sessionrecorder.Recorder)
}

func TestSSHChannelPair_serve_Success(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Create mock channels
		sourceChannel := NewMockChannel()
		targetChannel := NewMockChannel()

		// Create mock request channels
		sourceRequests := make(chan Request)
		targetRequests := make(chan Request)

		mockRecorderFactory := &mockSessionRecorderFactory{}
		mockRec := &mockRecorder{}

		mockRecorderFactory.On("NewRecorder", mock.Anything).Return(mockRec)
		mockRec.On("WriteHeader", mock.MatchedBy(func(header sessionrecorder.AsciicastHeader) bool {
			return header.Version == 2 &&
				header.User == "testuser" &&
				header.Width == 80 &&
				header.Height == 24 &&
				header.Command == "shell"
		})).Return(nil)
		mockRec.On("WriteOutputEvent", mock.MatchedBy(func(data []byte) bool {
			return bytes.Equal(data, []byte("filename.txt"))
		})).Return(nil)
		mockRec.On("WriteResizeEvent",
			mock.MatchedBy(func(width int) bool { return width == 100 }),
			mock.MatchedBy(func(height int) bool { return height == 44 }),
		).Return(nil)
		mockRec.On("Stop").Return()

		channelPair := NewSSHChannelPair(
			zap.NewNop(),
			"testuser",
			sourceChannel,
			sourceRequests,
			targetChannel,
			targetRequests,
			"session",
			"downstream",
			"upstream",
		)
		channelPair.recorderFactory = mockRecorderFactory

		// Run serve in a goroutine
		done := make(chan struct{})

		go func() {
			defer close(done)

			channelPair.serve()
		}()

		// Send pty-req request
		ptyRequest := &mockSSHRequest{
			Type:      "pty-req",
			Payload:   ssh.Marshal(ptyReq{WidthColumns: 80, HeightRows: 24}),
			WantReply: true,
		}
		ptyRequest.On("Reply", true, []byte(nil)).Return(nil)

		sourceRequests <- ptyRequest

		// Assert that the pty request was sent to target
		synctest.Wait()

		requests := targetChannel.GetSendRequests()

		assert.Len(t, requests, 1)
		assert.Equal(t, ptyRequest.Type, requests[0].Type)
		assert.Equal(t, ptyRequest.Payload, requests[0].Payload)
		assert.True(t, requests[0].WantReply)

		// Send shell request to start the session
		shellRequest := &mockSSHRequest{
			Type:      "shell",
			Payload:   []byte{},
			WantReply: true,
		}
		shellRequest.On("Reply", true, []byte(nil)).Return(nil)

		sourceRequests <- shellRequest

		// Assert that the shell request was sent to target
		synctest.Wait()

		requests = targetChannel.GetSendRequests()

		assert.Len(t, requests, 2)
		assert.Equal(t, shellRequest.Type, requests[1].Type)
		assert.Equal(t, shellRequest.Payload, requests[1].Payload)
		assert.True(t, requests[1].WantReply)

		// Send window-change request
		windowChangeRequest := &mockSSHRequest{
			Type:      "window-change",
			Payload:   ssh.Marshal(windowChangeReq{WidthColumns: 100, HeightRows: 44}),
			WantReply: false,
		}
		windowChangeRequest.On("Reply", false, []byte(nil)).Return(nil)

		sourceRequests <- windowChangeRequest

		// Assert that the window-change request was sent to target
		synctest.Wait()

		requests = targetChannel.GetSendRequests()

		assert.Len(t, requests, 3)
		assert.Equal(t, windowChangeRequest.Type, requests[2].Type)
		assert.Equal(t, windowChangeRequest.Payload, requests[2].Payload)
		assert.False(t, requests[2].WantReply)

		// Write data to the target channel
		targetChannel.SetData([]byte("filename.txt"))
		// Assert that the data was copied to the source channel
		synctest.Wait()
		assert.Equal(t, []byte("filename.txt"), sourceChannel.GetWrittenData())

		// Send exit-status back
		exitStatus := &mockSSHRequest{
			Type:      "exit-status",
			Payload:   []byte{},
			WantReply: false,
		}
		targetRequests <- exitStatus

		// Assert that the exit-status request was sent to source
		synctest.Wait()

		requests = sourceChannel.GetSendRequests()

		assert.Len(t, requests, 1)
		assert.Equal(t, exitStatus.Type, requests[0].Type)
		assert.Equal(t, exitStatus.Payload, requests[0].Payload)
		assert.False(t, requests[0].WantReply)

		// Close all the channels now
		_ = targetChannel.Close()

		close(targetRequests)

		_ = sourceChannel.Close()

		close(sourceRequests)

		// Wait for serve to complete
		<-done

		// Check for proper recording
		mockRecorderFactory.AssertExpectations(t)
		mockRec.AssertExpectations(t)
	})
}

func TestSSHChannelPair_serve_NonShellCommand(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Create mock channels
		sourceChannel := NewMockChannel()
		targetChannel := NewMockChannel()

		// Create mock request channels
		sourceRequests := make(chan Request)
		targetRequests := make(chan Request)

		mockRecorderFactory := &mockSessionRecorderFactory{}

		channelPair := NewSSHChannelPair(
			zap.NewNop(),
			"testuser",
			sourceChannel,
			sourceRequests,
			targetChannel,
			targetRequests,
			"session",
			"downstream",
			"upstream",
		)
		channelPair.recorderFactory = mockRecorderFactory

		// Run serve in a goroutine
		done := make(chan struct{})

		go func() {
			defer close(done)

			channelPair.serve()
		}()

		// Send subsystem request to start the session
		subsystemRequest := &mockSSHRequest{
			Type:      "subsystem",
			Payload:   ssh.Marshal(subsystemReq{Name: "sftp"}),
			WantReply: true,
		}
		subsystemRequest.On("Reply", true, []byte(nil)).Return(nil)

		sourceRequests <- subsystemRequest

		// Assert that the subsystem request was sent to target
		synctest.Wait()

		requests := targetChannel.GetSendRequests()

		assert.Len(t, requests, 1)
		assert.Equal(t, subsystemRequest.Type, requests[0].Type)
		assert.Equal(t, subsystemRequest.Payload, requests[0].Payload)
		assert.Equal(t, subsystemRequest.WantReply, requests[0].WantReply)

		// Close all the channels now
		_ = targetChannel.Close()

		close(targetRequests)

		_ = sourceChannel.Close()

		close(sourceRequests)

		// Wait for serve to complete
		<-done

		// Check that recorder was not called for non-shell command
		mockRecorderFactory.AssertNotCalled(t, "NewRecorder")
	})
}

func TestSSHChannelPair_serve_SessionStartTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Create mock channels
		sourceChannel := NewMockChannel()
		targetChannel := NewMockChannel()

		// Create mock request channels
		sourceRequests := make(chan Request)
		targetRequests := make(chan Request)

		mockRecorderFactory := &mockSessionRecorderFactory{}

		// Recorder factory should NOT be called since we timeout before creating recorder
		mockRecorderFactory.AssertNotCalled(t, "NewRecorder")

		channelPair := NewSSHChannelPair(
			zap.NewNop(),
			"testuser",
			sourceChannel,
			sourceRequests,
			targetChannel,
			targetRequests,
			"session",
			"downstream",
			"upstream",
		)
		channelPair.recorderFactory = mockRecorderFactory

		// Run serve in a goroutine
		done := make(chan struct{})

		go func() {
			defer close(done)

			channelPair.serve()
		}()

		time.Sleep(sessionStartTimeout)
		synctest.Wait()

		// Don't send any session start requests - this should cause a timeout
		// The serve() method waits for a session to start but we never send one

		// Wait for serve to complete (should timeout and return early)
		select {
		case <-done:
			// Success - serve should complete due to timeout prior to the timer below
		default:
			t.Fatal("serve() did not complete within timeout")
		}

		// Close channels for cleanup
		_ = targetChannel.Close()

		close(targetRequests)

		_ = sourceChannel.Close()

		close(sourceRequests)

		// Verify expectations - recorder should never have been created
		mockRecorderFactory.AssertExpectations(t)
	})
}
