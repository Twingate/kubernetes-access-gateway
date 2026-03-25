// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"sync"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	labelDownstream = "downstream"
	labelUpstream   = "upstream"
)

// Denylists for channel types per direction (RFC 4254).
var (
	// disallowedDownstreamChannelTypes are channel types not allowed from downstream client.
	disallowedDownstreamChannelTypes = map[string]bool{
		"x11":             true, // server→client per RFC 4254 §6.3.2
		"forwarded-tcpip": true, // server→client per RFC 4254 §7.2
	}

	// disallowedUpstreamChannelTypes are channel types not allowed from upstream server.
	disallowedUpstreamChannelTypes = map[string]bool{
		"session":      true, // client→server per RFC 4254 §6.1
		"direct-tcpip": true, // client→server per RFC 4254 §7.2
		"x11":          true, // not supported by gateway
	}
)

// Denylists for global request types per direction (RFC 4254).
var (
	// disallowedUpstreamGlobalRequests are global request types not allowed from upstream server.
	disallowedUpstreamGlobalRequests = map[string]bool{
		"tcpip-forward":        true, // client→server per RFC 4254 §7.1
		"cancel-tcpip-forward": true, // client→server per RFC 4254 §7.1
	}
)

// ChannelPairFactory creates SSH channel pairs.
type ChannelPairFactory interface {
	NewChannelPair(logger *zap.Logger, sshUsername string, sourceChannel ssh.Channel, sourceRequests <-chan *ssh.Request, targetChannel ssh.Channel, targetRequests <-chan *ssh.Request, channelType string, sourceLabel, targetLabel string) ChannelPair
}

// DefaultChannelPairFactory implements ChannelPairFactory using SSHChannelPair.
type DefaultChannelPairFactory struct{}

//nolint:ireturn,revive // argument-limit: to be addressed when removing the ChannelPairFactory test interface
func (f *DefaultChannelPairFactory) NewChannelPair(logger *zap.Logger, sshUsername string, sourceChannel ssh.Channel, sourceRequests <-chan *ssh.Request, targetChannel ssh.Channel, targetRequests <-chan *ssh.Request, channelType string, sourceLabel, targetLabel string) ChannelPair {
	return NewSSHChannelPair(
		logger,
		sshUsername,
		sourceChannel,
		wrapSSHRequestChannel(sourceRequests),
		targetChannel,
		wrapSSHRequestChannel(targetRequests),
		channelType,
		sourceLabel,
		targetLabel,
	)
}

type ConnPair interface {
	serve()
	close()
}

type SSHConnPair struct {
	logger *zap.Logger

	// Downstream SSH connection, channels, and global requests
	downstreamConn            ssh.Conn
	downstreamSSHChannelsChan <-chan ssh.NewChannel
	downstreamRequestsChan    <-chan *ssh.Request

	// Upstream SSH connection, channels, and global requests
	upstreamConn            ssh.Conn
	upstreamSSHChannelsChan <-chan ssh.NewChannel
	upstreamRequestsChan    <-chan *ssh.Request

	// Factory for creating channel pairs
	channelPairFactory ChannelPairFactory

	// Wait group for all channel pairs to be finished
	wg sync.WaitGroup
}

func NewSSHConnPair(
	logger *zap.Logger,
	downstreamConn ssh.Conn, downstreamChannels <-chan ssh.NewChannel, downstreamRequests <-chan *ssh.Request,
	upstreamConn ssh.Conn, upstreamChannels <-chan ssh.NewChannel, upstreamRequests <-chan *ssh.Request,
) *SSHConnPair {
	return &SSHConnPair{
		logger:                    logger,
		downstreamConn:            downstreamConn,
		downstreamSSHChannelsChan: downstreamChannels,
		downstreamRequestsChan:    downstreamRequests,
		upstreamConn:              upstreamConn,
		upstreamSSHChannelsChan:   upstreamChannels,
		upstreamRequestsChan:      upstreamRequests,
		channelPairFactory:        &DefaultChannelPairFactory{},
	}
}

func (c *SSHConnPair) serve() {
	// Forward global requests in both directions
	c.wg.Go(func() {
		c.forwardGlobalRequests(c.downstreamRequestsChan, c.upstreamConn, nil, labelDownstream, labelUpstream)
	})

	c.wg.Go(func() {
		c.forwardGlobalRequests(c.upstreamRequestsChan, c.downstreamConn, disallowedUpstreamGlobalRequests, labelUpstream, labelDownstream)
	})

	// Forward channels in both directions
	c.wg.Go(func() {
		c.forwardChannels(c.downstreamSSHChannelsChan, c.upstreamConn, disallowedDownstreamChannelTypes, labelDownstream, labelUpstream)
	})

	c.wg.Go(func() {
		c.forwardChannels(c.upstreamSSHChannelsChan, c.downstreamConn, disallowedUpstreamChannelTypes, labelUpstream, labelDownstream)
	})

	c.wg.Wait()
}

func (c *SSHConnPair) forwardChannels(channels <-chan ssh.NewChannel, targetConn ssh.Conn, disallowedTypes map[string]bool, source, target string) {
	logger := c.logger.With(zap.String("conn_source", source), zap.String("conn_target", target))

	for newChannel := range channels {
		channelType := newChannel.ChannelType()
		logger.Debug("Handling channel", zap.String("channelType", channelType))

		if disallowedTypes[channelType] {
			logger.Warn("Rejecting disallowed channel type", zap.String("channelType", channelType))

			if err := newChannel.Reject(ssh.Prohibited, "channel type not allowed"); err != nil {
				logger.Error("Failed to reject channel", zap.Error(err))
			}

			continue
		}

		targetChannel, targetRequests, err := targetConn.OpenChannel(channelType, newChannel.ExtraData())
		if err != nil {
			logger.Error("Failed to open target channel", zap.Error(err))

			if err := newChannel.Reject(ssh.ConnectionFailed, "failed to open target channel"); err != nil {
				logger.Error("Failed to reject source channel", zap.Error(err))
			}

			continue
		}

		sourceChannel, sourceRequests, err := newChannel.Accept()
		if err != nil {
			logger.Error("Failed to accept source channel", zap.Error(err))

			if err := targetChannel.Close(); err != nil {
				logger.Error("Failed to close target channel", zap.Error(err))
			}

			go ssh.DiscardRequests(targetRequests)

			continue
		}

		channelID := uuid.New().String()
		logger.Debug("Serving channel pair", zap.String("channel_pair_id", channelID))

		channelPair := c.channelPairFactory.NewChannelPair(
			logger.With(zap.String("channel_pair_id", channelID)),
			c.upstreamConn.User(),
			sourceChannel, sourceRequests,
			targetChannel, targetRequests,
			channelType,
			source, target,
		)

		c.wg.Go(func() {
			channelPair.serve()
		})
	}
}

func (c *SSHConnPair) forwardGlobalRequests(requests <-chan *ssh.Request, dst ssh.Conn, disallowedTypes map[string]bool, source, target string) {
	logger := c.logger.With(zap.String("conn_source", source), zap.String("conn_target", target))

	for req := range requests {
		if disallowedTypes[req.Type] {
			logger.Warn("Rejecting disallowed global request", zap.String("type", req.Type))
			replyToGlobalRequest(req, false, nil, logger)

			continue
		}

		logger.Debug("Forwarding global request", zap.String("type", req.Type))

		ok, payload, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			logger.Error("Failed to forward global request", zap.String("type", req.Type), zap.Error(err))
			replyToGlobalRequest(req, false, nil, logger)

			continue
		}

		replyToGlobalRequest(req, ok, payload, logger)
	}
}

func (c *SSHConnPair) close() {
	err := c.downstreamConn.Close()
	if err != nil {
		c.logger.Error("Failed to close downstream connection", zap.Error(err))
	}

	err = c.upstreamConn.Close()
	if err != nil {
		c.logger.Error("Failed to close upstream connection", zap.Error(err))
	}
}

func replyToGlobalRequest(req *ssh.Request, ok bool, payload []byte, logger *zap.Logger) {
	if !req.WantReply {
		return
	}

	if err := req.Reply(ok, payload); err != nil {
		logger.Error("Failed to reply to global request", zap.Error(err))
	}
}
