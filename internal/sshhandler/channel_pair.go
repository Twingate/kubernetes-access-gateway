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

	channelType string

	// Source SSH channel
	sourceChannel ssh.Channel
	// Source SSH channel requests channel
	sourceChannelRequests <-chan Request

	// Target SSH channel
	targetChannel ssh.Channel
	// Target SSH channel requests channel
	targetChannelRequests <-chan Request

	// SSH username (for session recording)
	sshUsername string

	// Labels for logging (e.g. "downstream", "upstream")
	sourceLabel string
	targetLabel string

	// Factory for creating session recorders
	recorderFactory SessionRecorderFactory

	ptyRequestOnce sync.Once
}

// NewSSHChannelPair creates a new SSHChannelPair with the default factories.
func NewSSHChannelPair(logger *zap.Logger, sshUsername string, sourceChannel ssh.Channel, sourceRequests <-chan Request, targetChannel ssh.Channel, targetRequests <-chan Request, channelType string, sourceLabel, targetLabel string) *SSHChannelPair {
	return &SSHChannelPair{
		logger:                logger,
		sshUsername:           sshUsername,
		sourceChannel:         sourceChannel,
		sourceChannelRequests: sourceRequests,
		targetChannel:         targetChannel,
		targetChannelRequests: targetRequests,
		recorderFactory:       &DefaultSessionRecorderFactory{},
		channelType:           channelType,
		sourceLabel:           sourceLabel,
		targetLabel:           targetLabel,
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
		User:      c.sshUsername,
	}

	// Handle the source channel's requests
	sourceEOFTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)
	sourceRequestHandler := &SSHRequestHandler{
		logger:            c.logger.With(zap.String("request_source", c.sourceLabel), zap.String("request_target", c.targetLabel)),
		flushTrigger:      sourceEOFTrigger,
		sourceRequestChan: c.sourceChannelRequests,
		targetChannel:     c.targetChannel,
		onPtyRequest: func(req ptyReq) {
			// Set the asciinema header with the pty request details only once
			c.ptyRequestOnce.Do(func() {
				asciinemaHeader.Width = int(req.WidthColumns)
				asciinemaHeader.Height = int(req.HeightRows)
			})
		},
		onWindowChange: func(req windowChangeReq) {
			recMu.RLock()

			r := rec

			recMu.RUnlock()

			if r == nil {
				return
			}

			if err := r.WriteResizeEvent(int(req.WidthColumns), int(req.HeightRows)); err != nil {
				c.logger.Error("failed to write resize event", zap.Error(err))
			}
		},
	}
	sourceSessionSignals := sourceRequestHandler.handleRequests()

	// Handle the target channel's requests
	targetEOFTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)
	targetRequestHandler := &SSHRequestHandler{
		logger:            c.logger.With(zap.String("request_source", c.targetLabel), zap.String("request_target", c.sourceLabel)),
		flushTrigger:      targetEOFTrigger,
		sourceRequestChan: c.targetChannelRequests,
		targetChannel:     c.sourceChannel,
		onPtyRequest:      nil,
		onWindowChange:    nil,
	}
	targetSessionSignals := targetRequestHandler.handleRequests()

	var command string

	if c.channelType == "session" {
		// Wait for session to start from source prior to starting the data copying
		select {
		case command = <-sourceSessionSignals.started:
			c.logger.Debug("Source session started", zap.String("command", command))
			asciinemaHeader.Command = command
		case <-time.After(sessionStartTimeout):
			c.logger.Error("Timeout waiting for source session to start")

			return
		}
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
		// in the onPtyRequest() callback on the sourceRequestHandler
		err := rec.WriteHeader(asciinemaHeader)
		if err != nil {
			c.logger.Error("failed to write asciinema header", zap.Error(err))
		}

		processor = &TerminalOutputRecorder{recorder: rec}
	}

	copier := &BidirectionalCopier{
		logger: c.logger,
		SourceToTarget: ChannelCopyPair{
			logger:          c.logger,
			Src:             c.sourceChannel,
			Dst:             c.targetChannel,
			EOFTriggerCh:    sourceEOFTrigger,
			ChannelClosedCh: sourceSessionSignals.finished,
		},

		TargetToSource: ChannelCopyPair{
			logger:          c.logger,
			Src:             c.targetChannel,
			Dst:             c.sourceChannel,
			EOFTriggerCh:    targetEOFTrigger,
			ChannelClosedCh: targetSessionSignals.finished,
			Tap:             processor,
		},
	}

	copier.start()
}
