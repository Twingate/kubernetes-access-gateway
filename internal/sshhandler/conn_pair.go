// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"sync"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// ChannelPairFactory creates SSH channel pairs.
type ChannelPairFactory interface {
	NewChannelPair(logger *zap.Logger, upstreamSSHUsername string, downstreamChannel ssh.Channel, downstreamRequests <-chan *ssh.Request, upstreamChannel ssh.Channel, upstreamRequests <-chan *ssh.Request) ChannelPair
}

// DefaultChannelPairFactory implements ChannelPairFactory using SSHChannelPair.
type DefaultChannelPairFactory struct{}

//nolint:ireturn
func (f *DefaultChannelPairFactory) NewChannelPair(logger *zap.Logger, upstreamSSHUsername string, downstreamChannel ssh.Channel, downstreamRequests <-chan *ssh.Request, upstreamChannel ssh.Channel, upstreamRequests <-chan *ssh.Request) ChannelPair {
	return NewSSHChannelPair(
		logger,
		upstreamSSHUsername,
		downstreamChannel,
		wrapSSHRequestChannel(downstreamRequests),
		upstreamChannel,
		wrapSSHRequestChannel(upstreamRequests),
	)
}

type ConnPair interface {
	serve()
	close()
}

type SSHConnPair struct {
	logger *zap.Logger

	// The downstream SSH connection
	downstreamConn ssh.Conn

	// The upstream SSH connection
	upstreamConn ssh.Conn

	// Downstream SSH channel requests channel
	downstreamSSHChannelsChan <-chan ssh.NewChannel

	// Factory for creating channel pairs
	channelPairFactory ChannelPairFactory

	// Wait group for all channel pairs to be finished
	wg sync.WaitGroup
}

func NewSSHConnPair(logger *zap.Logger, downstreamConn ssh.Conn, upstreamConn ssh.Conn, downstreamChannels <-chan ssh.NewChannel) *SSHConnPair {
	return &SSHConnPair{
		logger:                    logger,
		downstreamConn:            downstreamConn,
		upstreamConn:              upstreamConn,
		downstreamSSHChannelsChan: downstreamChannels,
		channelPairFactory:        &DefaultChannelPairFactory{},
		wg:                        sync.WaitGroup{},
	}
}

func (c *SSHConnPair) serve() {
	// Start accepting SSH channels (SSH_MSG_CHANNEL_OPEN) from
	// the downstream SSH connection's go channel
	for newDownstreamChannel := range c.downstreamSSHChannelsChan {
		c.logger.Debug("New channel", zap.String("channelType", newDownstreamChannel.ChannelType()))
		// We expect a "session" channel according to RFC 4524:
		// https://datatracker.ietf.org/doc/html/rfc4254#section-6.1
		//      byte      SSH_MSG_CHANNEL_OPEN
		//      string    "session"
		// 		...
		// otherwise we reject this channel type
		if newDownstreamChannel.ChannelType() != "session" {
			err := newDownstreamChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			if err != nil {
				c.logger.Error("Failed to reject channel", zap.Error(err))
			}

			continue
		}

		// Create a new session channel on the upstream SSH server using upstreamConn.OpenChannel(),
		// this function is responsible for sending SSH_MSG_CHANNEL_OPEN
		upstreamChannel, upstreamRequests, err := c.upstreamConn.OpenChannel("session", nil)
		if err != nil {
			c.logger.Error("Failed to create upstream session", zap.Error(err))

			err := newDownstreamChannel.Reject(ssh.ConnectionFailed, "failed to create upstream session")
			if err != nil {
				c.logger.Error("Failed to reject downstream channel", zap.Error(err))
			}

			continue
		}

		// Accept the downstream channel session once we have established the upstream session
		downstreamChannel, downstreamRequests, err := newDownstreamChannel.Accept()
		if err != nil {
			c.logger.Error("Could not accept channel", zap.Error(err))

			err := newDownstreamChannel.Reject(ssh.ConnectionFailed, "failed to accept channel")
			if err != nil {
				c.logger.Error("Failed to reject downstream channel", zap.Error(err))
			}

			continue
		}

		channelID := uuid.New().String()
		c.logger.Debug("Serving channel pair", zap.String("channel_pair_id", channelID))

		// Create the downstream/upstream channel pair using the factory
		channelPair := c.channelPairFactory.NewChannelPair(
			c.logger.With(zap.String("channel_pair_id", channelID)),
			c.upstreamConn.User(),
			downstreamChannel,
			downstreamRequests,
			upstreamChannel,
			upstreamRequests,
		)

		// Serve the channel pair in a new goroutine

		c.wg.Go(func() {
			channelPair.serve()
		})
	}

	// Wait for all channel pairs to finish
	c.wg.Wait()
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
