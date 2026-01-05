// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	requestTypePty          = "pty-req"
	requestTypeShell        = "shell"
	requestTypeExec         = "exec"
	requestTypeSubsystem    = "subsystem"
	requestTypeWindowChange = "window-change"
)

// Request interface abstracts ssh.Request.
type Request interface {
	GetType() string
	GetWantReply() bool
	GetPayload() []byte
	Reply(ok bool, message []byte) error
}

// sshRequest wraps ssh.Request to implement Request interface.
type sshRequest struct {
	*ssh.Request
}

func (w *sshRequest) GetType() string {
	return w.Type
}

func (w *sshRequest) GetWantReply() bool {
	return w.WantReply
}

func (w *sshRequest) GetPayload() []byte {
	return w.Payload
}

func (w *sshRequest) Reply(ok bool, message []byte) error {
	return w.Request.Reply(ok, message)
}

// wrapSSHRequestChannel wraps a channel of *ssh.Request into a channel of Request.
func wrapSSHRequestChannel(sshChan <-chan *ssh.Request) <-chan Request {
	wrappedChan := make(chan Request)

	go func() {
		defer close(wrappedChan)

		for req := range sshChan {
			wrappedChan <- &sshRequest{Request: req}
		}
	}()

	return wrappedChan
}

type SSHSessionSignals struct {
	started  chan string // The command that started the session
	finished chan struct{}
}

type SSHRequestHandlerFlushTrigger struct {
	cb func()
}

// SSH pty request structure
// see: https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
type ptyReq struct {
	Term         string
	WidthColumns uint32
	HeightRows   uint32
	WidthPixels  uint32
	HeightPixels uint32
	Modelist     string
}

// SSH exec request structure
// see: https://datatracker.ietf.org/doc/html/rfc4254#section-6.5
type execReq struct {
	Command string
}

// SSH subsystem request structure
// see: https://datatracker.ietf.org/doc/html/rfc4254#section-6.5
type subsystemReq struct {
	Name string
}

// SSH window-change request structure
// see: https://datatracker.ietf.org/doc/html/rfc4254#section-6.7
type windowChangeReq struct {
	WidthColumns uint32
	HeightRows   uint32
	WidthPixels  uint32
	HeightPixels uint32
}

// RequestHandler defines the interface for handling SSH channel requests.
type RequestHandler interface {
	// handleRequests processes SSH channel requests and returns session signals
	handleRequests() SSHSessionSignals
}

// parseRequestPayload unmarshals request payload and logs error if parsing fails.
func (h *SSHRequestHandler) parseRequestPayload(req Request, target any) {
	if err := ssh.Unmarshal(req.GetPayload(), target); err != nil {
		h.logger.Error("Failed to parse "+req.GetType()+" request", zap.Error(err))
	}
}

// handleRequest processes and forwards a single SSH request, returning session info if applicable.
func (h *SSHRequestHandler) handleRequest(req Request, sessionSignals SSHSessionSignals) {
	h.logger.Debug("Channel request", zap.String("type", req.GetType()))

	// Sessions are started when a shell, exec, or subsystem request is received
	// see: https://datatracker.ietf.org/doc/html/rfc4254#section-6.5
	sessionStarted := false
	command := ""

	shouldLog := false
	requestFields := map[string]any{
		"type": req.GetType(),
	}

	switch req.GetType() {
	case requestTypePty:
		var ptyReq ptyReq
		h.parseRequestPayload(req, &ptyReq)

		h.onPtyRequest(ptyReq)

		shouldLog = true
	case requestTypeShell:
		sessionStarted = true
		command = req.GetType()

		shouldLog = true
	case requestTypeExec:
		sessionStarted = true

		var execReq execReq
		h.parseRequestPayload(req, &execReq)

		command = req.GetType() + " " + execReq.Command

		shouldLog = true
		requestFields["command"] = execReq.Command
	case requestTypeSubsystem:
		sessionStarted = true

		var subsystemReq subsystemReq
		h.parseRequestPayload(req, &subsystemReq)

		command = req.GetType() + " " + subsystemReq.Name

		shouldLog = true
		requestFields["name"] = subsystemReq.Name
	case requestTypeWindowChange:
		var windowChangeReq windowChangeReq
		h.parseRequestPayload(req, &windowChangeReq)

		h.onWindowChange(windowChangeReq)
	default:
		// No special handling
	}

	if shouldLog {
		h.logger.Info("Received SSH request", zap.Any("request", requestFields))
	}

	if err := forwardRequest(h.targetChannel, req); err != nil {
		h.logger.Error("Failed to forward request", zap.Error(err))

		return
	}

	// Close the session started channel to signal that the session has started
	if sessionStarted {
		sessionSignals.started <- command

		close(sessionSignals.started)
	}
}

type SSHRequestHandler struct {
	logger *zap.Logger

	// Trigger used to flush any pending requests
	flushTrigger <-chan SSHRequestHandlerFlushTrigger

	// Go Channel to process incoming SSH channel requests from
	sourceRequestChan <-chan Request

	// Target SSH channel to forward SSH channel requests to
	targetChannel ssh.Channel

	// Callback for when a pty request is received providing the width and height of the terminal
	onPtyRequest func(req ptyReq)

	// Callback for when a window-change request is received
	onWindowChange func(req windowChangeReq)
}

// Processes SSH channel requests from the source go channel and forwards them to the target SSH channel
// on a separate goroutine.
func (h *SSHRequestHandler) handleRequests() SSHSessionSignals {
	sessionSignals := SSHSessionSignals{
		started:  make(chan string, 1),
		finished: make(chan struct{}),
	}

	go func() {
		defer close(sessionSignals.finished)

		for {
			select {
			case req, ok := <-h.sourceRequestChan:
				if !ok {
					// Request channel closed, we are finished
					return
				}
				// Forward the request
				h.handleRequest(req, sessionSignals)

			case trigger, ok := <-h.flushTrigger:
				if !ok {
					h.logger.Error("Flush trigger channel closed prematurely")

					return
				}

				// Drain any immediately available requests
				draining := true
				for draining {
					select {
					case req, ok := <-h.sourceRequestChan:
						if !ok {
							// Request channel closed, we are finished
							draining = false
						} else {
							// Forward the request
							h.handleRequest(req, sessionSignals)
						}
					// Make select non-blocking, will enter here when there are no more requests to drain
					default:
						draining = false
					}
				}
				// Call the callback to signal that we have drained any pending requests
				trigger.cb()
			}
		}
	}()

	return sessionSignals
}

func forwardRequest(channel ssh.Channel, request Request) error {
	// Forward the request to the target channel
	reply, requestErr := channel.SendRequest(request.GetType(), request.GetWantReply(), request.GetPayload())
	if requestErr != nil {
		// Reply with failure
		if request.GetWantReply() {
			_ = request.Reply(false, nil)
		}

		return requestErr
	}

	// Reply to the original request with the reply from forwarded request
	if request.GetWantReply() {
		if replyErr := request.Reply(reply, nil); replyErr != nil {
			return replyErr
		}
	}

	return nil
}
