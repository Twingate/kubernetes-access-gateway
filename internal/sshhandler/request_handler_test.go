// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/ssh"
)

func createPtyRequestPayload() []byte {
	ptyReq := ptyReq{
		Term:         "xterm-256color",
		WidthColumns: 80,
		HeightRows:   24,
		WidthPixels:  640,
		HeightPixels: 480,
		Modelist:     "",
	}
	payload := ssh.Marshal(ptyReq)

	return payload
}

func createExecRequestPayload(command string) []byte {
	execReq := execReq{
		Command: command,
	}
	payload := ssh.Marshal(execReq)

	return payload
}

func createSubsystemRequestPayload(name string) []byte {
	subsystemReq := subsystemReq{
		Name: name,
	}
	payload := ssh.Marshal(subsystemReq)

	return payload
}

func createWindowChangeRequestPayload() []byte {
	windowChangeReq := windowChangeReq{
		WidthColumns: 80,
		HeightRows:   24,
		WidthPixels:  640,
		HeightPixels: 480,
	}
	payload := ssh.Marshal(windowChangeReq)

	return payload
}

func TestSSHRequestHandler_handleRequests_PtyRequest(t *testing.T) {
	t.Parallel()
	mockChannel := NewMockChannel()
	sourceRequestChan := make(chan Request, 1)
	flushTrigger := make(chan SSHRequestHandlerFlushTrigger)
	core, logs := observer.New(zap.DebugLevel)

	var capturedPtyReq ptyReq

	onPtyRequest := func(req ptyReq) {
		capturedPtyReq = req
	}

	handler := &SSHRequestHandler{
		logger:            zap.New(core).Named("test"),
		flushTrigger:      flushTrigger,
		sourceRequestChan: sourceRequestChan,
		targetChannel:     mockChannel,
		onPtyRequest:      onPtyRequest,
	}

	// Create Pty Request
	ptyPayload := createPtyRequestPayload()
	mockReq := &mockSSHRequest{
		Type:      "pty-req",
		WantReply: true,
		Payload:   ptyPayload,
	}
	// We expect this to be forwarded to the target channel
	mockChannel.On("SendRequest", "pty-req", true, mock.AnythingOfType("[]uint8")).Return(true, nil)

	// We expect this to be replied to
	mockReq.On("Reply", true, []byte(nil)).Return(nil)

	// Provide the request to the handler
	signals := handler.handleRequests()

	sourceRequestChan <- mockReq

	// Close the channel
	close(sourceRequestChan)

	// Wait for request processing to be finished after closing the channel
	<-signals.finished

	// Verify pty request was processed
	assert.Equal(t, "xterm-256color", capturedPtyReq.Term)
	assert.Equal(t, uint32(80), capturedPtyReq.WidthColumns)
	assert.Equal(t, uint32(24), capturedPtyReq.HeightRows)

	mockChannel.AssertExpectations(t)

	// Assert that the SSH request log was emitted
	requestLog := logs.FilterMessage("Received SSH request").All()
	assert.Len(t, requestLog, 1)
	assert.Equal(t, map[string]any{"type": "pty-req"}, requestLog[0].ContextMap()["request"])
}

func TestSSHRequestHandler_handleRequests_ShellRequest(t *testing.T) {
	t.Parallel()
	mockChannel := NewMockChannel()
	sourceRequestChan := make(chan Request, 1)
	flushTrigger := make(chan SSHRequestHandlerFlushTrigger)
	core, logs := observer.New(zap.DebugLevel)

	handler := &SSHRequestHandler{
		logger:            zap.New(core).Named("test"),
		flushTrigger:      flushTrigger,
		sourceRequestChan: sourceRequestChan,
		targetChannel:     mockChannel,
		onPtyRequest:      func(_ ptyReq) {},
	}

	// Create shell request
	mockReq := &mockSSHRequest{
		Type:      "shell",
		WantReply: true,
		Payload:   nil,
	}

	// We expect this to be forwarded to the target channel
	mockChannel.On("SendRequest", "shell", true, []byte(nil)).Return(true, nil)

	// We expect this to be replied to
	mockReq.On("Reply", true, []byte(nil)).Return(nil)

	// Provide the request to the handler
	signals := handler.handleRequests()

	sourceRequestChan <- mockReq

	// Wait for session to start
	command := <-signals.started
	assert.Equal(t, "shell", command)

	// Close the channel
	close(sourceRequestChan)

	// Wait for processing to finish after closing the channel
	<-signals.finished

	mockChannel.AssertExpectations(t)

	// Assert that the SSH request log was emitted
	requestLog := logs.FilterMessage("Received SSH request").All()
	assert.Len(t, requestLog, 1)
	assert.Equal(t, map[string]any{"type": "shell"}, requestLog[0].ContextMap()["request"])
}

func TestSSHRequestHandler_handleRequests_ExecRequest(t *testing.T) {
	t.Parallel()
	mockChannel := NewMockChannel()
	sourceRequestChan := make(chan Request, 1)
	flushTrigger := make(chan SSHRequestHandlerFlushTrigger)
	core, logs := observer.New(zap.DebugLevel)

	handler := &SSHRequestHandler{
		logger:            zap.New(core).Named("test"),
		flushTrigger:      flushTrigger,
		sourceRequestChan: sourceRequestChan,
		targetChannel:     mockChannel,
		onPtyRequest:      func(_ ptyReq) {},
	}

	// Create and send exec request
	execPayload := createExecRequestPayload("ls -la")
	mockReq := &mockSSHRequest{
		Type:      "exec",
		WantReply: true,
		Payload:   execPayload,
	}
	// We expect this to be forwarded to the target channel
	mockChannel.On("SendRequest", "exec", true, mock.AnythingOfType("[]uint8")).Return(true, nil)
	// We expect this to be replied to
	mockReq.On("Reply", true, []byte(nil)).Return(nil)

	// Provide the request to the handler
	signals := handler.handleRequests()

	sourceRequestChan <- mockReq

	// Wait for session to start
	command := <-signals.started
	assert.Equal(t, "exec ls -la", command)

	// Close the channel
	close(sourceRequestChan)

	// Wait for processing to finish after closing the channel
	<-signals.finished

	mockChannel.AssertExpectations(t)

	// Assert that the SSH request log was emitted
	requestLog := logs.FilterMessage("Received SSH request").All()
	assert.Len(t, requestLog, 1)
	assert.Equal(t, map[string]any{"type": "exec", "command": "ls -la"}, requestLog[0].ContextMap()["request"])
}

func TestSSHRequestHandler_handleRequests_SubsystemRequest(t *testing.T) {
	t.Parallel()
	mockChannel := NewMockChannel()
	sourceRequestChan := make(chan Request, 1)
	flushTrigger := make(chan SSHRequestHandlerFlushTrigger)
	core, logs := observer.New(zap.DebugLevel)

	handler := &SSHRequestHandler{
		logger:            zap.New(core).Named("test"),
		flushTrigger:      flushTrigger,
		sourceRequestChan: sourceRequestChan,
		targetChannel:     mockChannel,
		onPtyRequest:      func(_ ptyReq) {},
	}

	// Create subsystem request
	subsystemPayload := createSubsystemRequestPayload("sftp")
	mockReq := &mockSSHRequest{
		Type:      "subsystem",
		WantReply: false,
		Payload:   subsystemPayload,
	}
	// We expect this to be forwarded to the target channel
	mockChannel.On("SendRequest", "subsystem", false, mock.AnythingOfType("[]uint8")).Return(true, nil)

	// Provide the request to the handler
	signals := handler.handleRequests()

	sourceRequestChan <- mockReq

	// Wait for session to start
	command := <-signals.started
	assert.Equal(t, "subsystem sftp", command)

	// Close the channel
	close(sourceRequestChan)

	// Wait for processing to finish after closing the channel
	<-signals.finished

	// Assert that Reply was NOT called since WantReply is false
	mockReq.AssertNotCalled(t, "Reply")
	mockChannel.AssertExpectations(t)

	// Assert that the SSH request log was emitted
	requestLog := logs.FilterMessage("Received SSH request").All()
	assert.Len(t, requestLog, 1)
	assert.Equal(t, map[string]any{"type": "subsystem", "name": "sftp"}, requestLog[0].ContextMap()["request"])
}

func TestSSHRequestHandler_handleRequests_WindowChangeRequest(t *testing.T) {
	t.Parallel()
	mockChannel := NewMockChannel()
	sourceRequestChan := make(chan Request, 1)
	flushTrigger := make(chan SSHRequestHandlerFlushTrigger)

	var capturedWindowChangeReq windowChangeReq

	onWindowChangeRequest := func(windowChangeReq windowChangeReq) {
		capturedWindowChangeReq = windowChangeReq
	}

	handler := &SSHRequestHandler{
		logger:            zap.NewNop(),
		flushTrigger:      flushTrigger,
		sourceRequestChan: sourceRequestChan,
		targetChannel:     mockChannel,
		onPtyRequest:      func(_ ptyReq) {},
		onWindowChange:    onWindowChangeRequest,
	}

	mockReq := &mockSSHRequest{
		Type:      "window-change",
		WantReply: false,
		Payload:   createWindowChangeRequestPayload(),
	}

	mockChannel.On("SendRequest", "window-change", false, mock.AnythingOfType("[]uint8")).Return(false, nil)

	mockReq.On("Reply", false, []byte(nil)).Return(nil)

	signals := handler.handleRequests()

	sourceRequestChan <- mockReq

	close(sourceRequestChan)

	// Wait for request processing to be finished after closing the channel
	<-signals.finished

	// Verify window-change request was processed
	assert.Equal(t, uint32(80), capturedWindowChangeReq.WidthColumns)
	assert.Equal(t, uint32(24), capturedWindowChangeReq.HeightRows)

	// Assert that Reply was NOT called since WantReply is false
	mockReq.AssertNotCalled(t, "Reply")
	mockChannel.AssertExpectations(t)
}

func TestSSHRequestHandler_handleRequests_FlushTrigger(t *testing.T) {
	t.Parallel()
	mockChannel := NewMockChannel()
	sourceRequestChan := make(chan Request, 3)
	flushTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)

	handler := &SSHRequestHandler{
		logger:            zap.NewNop(),
		flushTrigger:      flushTrigger,
		sourceRequestChan: sourceRequestChan,
		targetChannel:     mockChannel,
		onPtyRequest:      func(_ ptyReq) {},
	}

	// Set up mock expectations for multiple pty requests (non-session requests)
	mockChannel.On("SendRequest", "pty-req", true, mock.AnythingOfType("[]uint8")).Return(true, nil)
	mockChannel.On("SendRequest", "shell", true, mock.AnythingOfType("[]uint8")).Return(true, nil)

	signals := handler.handleRequests()

	// Send pty request and shell to be drained
	ptyPayload := createPtyRequestPayload()
	mockReq1 := &mockSSHRequest{
		Type:      "pty-req",
		WantReply: true,
		Payload:   ptyPayload,
	}
	mockReq1.On("Reply", true, []byte(nil)).Return(nil)

	mockReq2 := &mockSSHRequest{
		Type:      "shell",
		WantReply: true,
		Payload:   nil,
	}
	mockReq2.On("Reply", true, []byte(nil)).Return(nil)

	sourceRequestChan <- mockReq1

	sourceRequestChan <- mockReq2

	<-signals.started

	// Send flush trigger
	wg := sync.WaitGroup{}
	wg.Add(1)

	trigger := SSHRequestHandlerFlushTrigger{
		cb: func() {
			wg.Done()
		},
	}
	flushTrigger <- trigger

	// Wait for processing to finish
	wg.Wait()

	// Close source channel
	close(sourceRequestChan)

	// Wait for processing to finish
	<-signals.finished

	mockChannel.AssertExpectations(t)
}

func TestSSHRequestHandler_handleRequests_ChannelClosed(t *testing.T) {
	t.Parallel()
	mockChannel := NewMockChannel()
	sourceRequestChan := make(chan Request)
	flushTrigger := make(chan SSHRequestHandlerFlushTrigger)

	handler := &SSHRequestHandler{
		logger:            zap.NewNop(),
		flushTrigger:      flushTrigger,
		sourceRequestChan: sourceRequestChan,
		targetChannel:     mockChannel,
		onPtyRequest:      func(_ ptyReq) {},
	}

	signals := handler.handleRequests()

	// Close the source channel immediately
	close(sourceRequestChan)

	// Wait for processing to finish
	<-signals.finished

	// No mock expectations needed as no requests should be processed
	mockChannel.AssertExpectations(t)
}

func TestSSHRequestHandler_handleRequests_UnknownType(t *testing.T) {
	t.Parallel()
	mockChannel := NewMockChannel()
	sourceRequestChan := make(chan Request, 1)
	flushTrigger := make(chan SSHRequestHandlerFlushTrigger)
	core, logs := observer.New(zap.DebugLevel)

	handler := &SSHRequestHandler{
		logger:            zap.New(core).Named("test"),
		flushTrigger:      flushTrigger,
		sourceRequestChan: sourceRequestChan,
		targetChannel:     mockChannel,
		onPtyRequest:      func(_ ptyReq) {},
	}

	// Set up mock expectations
	mockChannel.On("SendRequest", "some-command", true, []byte("some random data")).Return(true, nil)

	// Create unknown type request with random data
	mockReq := &mockSSHRequest{
		Type:      "some-command",
		WantReply: true,
		Payload:   []byte("some random data"),
	}

	mockReq.On("Reply", true, []byte(nil)).Return(nil)

	signals := handler.handleRequests()

	sourceRequestChan <- mockReq

	close(sourceRequestChan)

	// Wait for processing to finish
	<-signals.finished

	mockChannel.AssertExpectations(t)

	// Assert that the SSH request log was not emitted
	requestLog := logs.FilterMessage("Received SSH request").All()
	assert.Empty(t, requestLog)
}

func TestForwardRequest_Failure(t *testing.T) {
	t.Parallel()
	mockChannel := NewMockChannel()

	mockReq := &mockSSHRequest{
		Type:      "exec",
		WantReply: true,
		Payload:   []byte("test"),
	}

	mockChannel.On("SendRequest", "exec", true, []byte("test")).Return(false, errors.New("send failed"))
	mockReq.On("Reply", false, []byte(nil)).Return(nil)

	err := forwardRequest(mockChannel, mockReq)

	require.Error(t, err)
	mockChannel.AssertExpectations(t)
	mockReq.AssertExpectations(t)
}

func TestForwardRequest_Success(t *testing.T) {
	t.Parallel()
	mockChannel := NewMockChannel()

	mockReq := &mockSSHRequest{
		Type:      "shell",
		WantReply: true,
		Payload:   nil,
	}

	mockChannel.On("SendRequest", "shell", true, []byte(nil)).Return(true, nil)
	mockReq.On("Reply", true, []byte(nil)).Return(nil)

	err := forwardRequest(mockChannel, mockReq)

	require.NoError(t, err)
	mockChannel.AssertExpectations(t)
	mockReq.AssertExpectations(t)
}
