// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"io"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"k8sgateway/internal/sessionrecorder"
)

var sessionStartTimeout = 10 * time.Second

// SessionRecorderFactory creates session recorders.
type SessionRecorderFactory interface {
	NewRecorder(logger *zap.Logger) sessionrecorder.Recorder
}

// DefaultSessionRecorderFactory implements SessionRecorderFactory.
type DefaultSessionRecorderFactory struct{}

//nolint:ireturn
func (f *DefaultSessionRecorderFactory) NewRecorder(logger *zap.Logger) sessionrecorder.Recorder {
	return sessionrecorder.NewRecorder(logger)
}

// TerminalOutputRecorder is used for tapping into the raw output of a channel.
type TerminalOutputRecorder struct {
	recorder sessionrecorder.Recorder
}

func (c *TerminalOutputRecorder) Write(p []byte) (n int, err error) {
	err = c.recorder.WriteOutputEvent(p)

	return len(p), err
}

type ChannelPair interface {
	serve()
}

type SSHChannelPair struct {
	logger *zap.Logger

	// Downstream SSH channel
	downstreamChannel ssh.Channel
	// Downstream SSH channel requests channel
	downstreamChannelRequests <-chan Request

	// Upstream SSH channel
	upstreamChannel ssh.Channel
	// Upstream SSH channel requests channel
	upstreamChannelRequests <-chan Request
	// Upstream SSH username (for session recording)
	upstreamSSHUsername string

	// Factory for creating session recorders
	recorderFactory SessionRecorderFactory

	ptyRequestOnce sync.Once
}

// NewSSHChannelPair creates a new SSHChannelPair with the default factories.
func NewSSHChannelPair(logger *zap.Logger, upstreamSSHUsername string, downstreamChannel ssh.Channel, downstreamRequests <-chan Request, upstreamChannel ssh.Channel, upstreamRequests <-chan Request) *SSHChannelPair {
	return &SSHChannelPair{
		logger:                    logger,
		upstreamSSHUsername:       upstreamSSHUsername,
		downstreamChannel:         downstreamChannel,
		downstreamChannelRequests: downstreamRequests,
		upstreamChannel:           upstreamChannel,
		upstreamChannelRequests:   upstreamRequests,
		recorderFactory:           &DefaultSessionRecorderFactory{},
	}
}

func (c *SSHChannelPair) serve() {
	var (
		rec   sessionrecorder.Recorder
		recMu sync.RWMutex
	)

	// Create default asciinema header
	asciinemaHeader := sessionrecorder.AsciicastHeader{
		Version:   2,
		Timestamp: time.Now().Unix(),
		User:      c.upstreamSSHUsername,
	}

	// Handle the downstream channel's requests
	downstreamEOFTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)
	downstreamRequestHandler := &SSHRequestHandler{
		logger:            c.logger.With(zap.String("direction", "downstream -> upstream")),
		flushTrigger:      downstreamEOFTrigger,
		sourceRequestChan: c.downstreamChannelRequests,
		targetChannel:     c.upstreamChannel,
		onPtyRequest: func(req ptyReq) {
			// Set the asciinema header with the pty request details only once
			c.ptyRequestOnce.Do(func() {
				asciinemaHeader.Width = int(req.Columns)
				asciinemaHeader.Height = int(req.Rows)
			})
		},
		onWindowChange: func(req windowChangeReq) {
			recMu.RLock()

			r := rec

			recMu.RUnlock()

			if r == nil {
				return
			}

			if err := r.WriteResizeEvent(int(req.Columns), int(req.Rows)); err != nil {
				c.logger.Error("failed to write resize event", zap.Error(err))
			}
		},
	}
	downstreamSessionSignals := downstreamRequestHandler.handleRequests()

	// Handle the upstream channel's requests
	upstreamEOFTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)
	upstreamRequestHandler := &SSHRequestHandler{
		logger:            c.logger.With(zap.String("direction", "upstream -> downstream")),
		flushTrigger:      upstreamEOFTrigger,
		sourceRequestChan: c.upstreamChannelRequests,
		targetChannel:     c.downstreamChannel,
		onPtyRequest:      nil,
		onWindowChange:    nil,
	}
	upstreamSessionSignals := upstreamRequestHandler.handleRequests()

	// Wait for session to start from downstream prior to starting the data copying
	var command string
	select {
	case command = <-downstreamSessionSignals.started:
		c.logger.Debug("Downstream session started", zap.String("command", command))
		asciinemaHeader.Command = command
	case <-time.After(sessionStartTimeout):
		c.logger.Error("Timeout waiting for downstream session to start")

		return
	}

	var processor io.Writer

	if command == requestTypeShell {
		recMu.Lock()

		rec = c.recorderFactory.NewRecorder(c.logger)

		recMu.Unlock()

		defer rec.Stop()

		// Write the asciinema header to the recorder
		// Note: We are relying on the convention that 'pty-req' will be sent prior to 'shell' requests,
		// so we should have already set the asciinema header with the pty request details
		// in the onPtyRequest() callback on the downstreamRequestHandler
		err := rec.WriteHeader(asciinemaHeader)
		if err != nil {
			c.logger.Error("failed to write asciinema header", zap.Error(err))
		}

		processor = &TerminalOutputRecorder{recorder: rec}
	}

	copier := &BidirectionalCopier{
		logger: c.logger,
		DownstreamToUpstream: ChannelCopyPair{
			logger:          c.logger.With(zap.String("direction", "downstream -> upstream")),
			Src:             c.downstreamChannel,
			Dst:             c.upstreamChannel,
			EOFTriggerCh:    downstreamEOFTrigger,
			ChannelClosedCh: downstreamSessionSignals.finished,
		},

		UpstreamToDownstream: ChannelCopyPair{
			logger:          c.logger.With(zap.String("direction", "upstream -> downstream")),
			Src:             c.upstreamChannel,
			Dst:             c.downstreamChannel,
			EOFTriggerCh:    upstreamEOFTrigger,
			ChannelClosedCh: upstreamSessionSignals.finished,
			Tap:             processor,
		},
	}

	copier.start()
}
