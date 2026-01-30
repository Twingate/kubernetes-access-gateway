// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type mockChannelPair struct {
	mock.Mock

	serveCalled chan struct{}
}

func newMockChannelPair() *mockChannelPair {
	return &mockChannelPair{
		serveCalled: make(chan struct{}, 1),
	}
}

func (m *mockChannelPair) serve() {
	m.Called()

	m.serveCalled <- struct{}{}
}

type mockChannelPairFactory struct {
	mock.Mock

	channelPair ChannelPair
}

func newMockChannelPairFactory(channelPair ChannelPair) *mockChannelPairFactory {
	return &mockChannelPairFactory{
		channelPair: channelPair,
	}
}

//nolint:ireturn
func (m *mockChannelPairFactory) NewChannelPair(logger *zap.Logger, upstreamSSHUsername string, downstreamChannel ssh.Channel, downstreamRequests <-chan *ssh.Request, upstreamChannel ssh.Channel, upstreamRequests <-chan *ssh.Request) ChannelPair {
	args := m.Called(logger, upstreamSSHUsername, downstreamChannel, downstreamRequests, upstreamChannel, upstreamRequests)

	return args.Get(0).(ChannelPair)
}

// Test helper to create a channel that sends mock NewChannel objects.
func createMockChannelChan(channels []ssh.NewChannel) <-chan ssh.NewChannel {
	ch := make(chan ssh.NewChannel, len(channels))
	for _, channel := range channels {
		ch <- channel
	}

	close(ch)

	return ch
}

func TestSSHConnPair_serve_SessionChannelSuccess(t *testing.T) {
	t.Parallel()
	downstreamConn := &mockSSHConn{user: "downstream-user"}
	upstreamConn := &mockSSHConn{user: "upstream-user"}

	// Create mock channels
	newChannel := newMockNewChannel("session")
	downstreamChannel := NewMockChannel()
	upstreamChannel := NewMockChannel()

	// Create request channels
	downstreamRequests := make(chan *ssh.Request)
	upstreamRequests := make(chan *ssh.Request)

	// Create mock channel pair
	mockChannelPair := newMockChannelPair()
	mockFactory := newMockChannelPairFactory(mockChannelPair)

	// Set up expectations
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return(upstreamChannel, (<-chan *ssh.Request)(upstreamRequests), nil)
	newChannel.On("Accept").Return(downstreamChannel, (<-chan *ssh.Request)(downstreamRequests), nil)
	mockFactory.On("NewChannelPair", mock.Anything, "upstream-user", downstreamChannel, (<-chan *ssh.Request)(downstreamRequests), upstreamChannel, (<-chan *ssh.Request)(upstreamRequests)).Return(mockChannelPair)
	mockChannelPair.On("serve").Return()

	// Create channel chan with one session channel
	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := &SSHConnPair{
		logger:                    zap.NewNop(),
		downstreamConn:            downstreamConn,
		upstreamConn:              upstreamConn,
		downstreamSSHChannelsChan: channelChan,
		channelPairFactory:        mockFactory,
	}

	// Run serve in a goroutine and wait for completion
	done := make(chan struct{})

	go func() {
		defer close(done)

		connPair.serve()
	}()

	// Wait for the channel pair serve to be called
	select {
	case <-mockChannelPair.serveCalled:
		// Success - channel pair serve was called
	case <-time.After(1 * time.Second):
		t.Fatal("Channel pair serve was not called within timeout")
	}

	// Wait for serve to complete
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("serve() did not complete within timeout")
	}

	// Verify expectations
	upstreamConn.AssertExpectations(t)
	newChannel.AssertExpectations(t)
	mockFactory.AssertExpectations(t)
	mockChannelPair.AssertExpectations(t)
}

func TestSSHConnPair_serve_RejectNonSessionChannel(t *testing.T) {
	t.Parallel()
	downstreamConn := &mockSSHConn{}
	upstreamConn := &mockSSHConn{}

	// Create mock channel with non-session type
	newChannel := newMockNewChannel("direct-tcpip")

	// Set up expectations - should reject the channel
	newChannel.On("Reject", ssh.UnknownChannelType, "unknown channel type").Return(nil)

	// Create channel chan with one non-session channel
	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := NewSSHConnPair(zap.NewNop(), downstreamConn, upstreamConn, channelChan)

	// Track if serve completes
	done := make(chan struct{})

	go func() {
		connPair.serve()
		close(done)
	}()

	// Wait for serve to complete
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("serve() did not complete within timeout")
	}

	newChannel.AssertExpectations(t)
	// upstreamConn should not be called since we reject before opening upstream
	upstreamConn.AssertNotCalled(t, "OpenChannel")
}

func TestSSHConnPair_serve_UpstreamOpenChannelFailure(t *testing.T) {
	t.Parallel()
	downstreamConn := &mockSSHConn{}
	upstreamConn := &mockSSHConn{}

	// Create mock channels
	newChannel := newMockNewChannel("session")

	// Set up expectations - upstream fails to open channel
	expectedErr := errors.New("upstream connection failed")
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return((*MockChannel)(nil), (<-chan *ssh.Request)(nil), expectedErr)
	newChannel.On("Reject", ssh.ConnectionFailed, "failed to create upstream session").Return(nil)

	// Create channel chan with one session channel
	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := NewSSHConnPair(zap.NewNop(), downstreamConn, upstreamConn, channelChan)

	// Track if serve completes
	done := make(chan struct{})

	go func() {
		connPair.serve()
		close(done)
	}()

	// Wait for serve to complete
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("serve() did not complete within timeout")
	}

	upstreamConn.AssertExpectations(t)
	newChannel.AssertExpectations(t)
}

func TestSSHConnPair_serve_DownstreamAcceptFailure(t *testing.T) {
	t.Parallel()
	downstreamConn := &mockSSHConn{}
	upstreamConn := &mockSSHConn{}

	// Create mock channels
	newChannel := newMockNewChannel("session")
	upstreamChannel := NewMockChannel()

	// Create request channels
	upstreamRequests := make(chan *ssh.Request)
	close(upstreamRequests)

	// Set up expectations
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return(upstreamChannel, (<-chan *ssh.Request)(upstreamRequests), nil)

	// Downstream accept fails
	expectedErr := errors.New("downstream accept failed")
	newChannel.On("Accept").Return((*MockChannel)(nil), (<-chan *ssh.Request)(nil), expectedErr)
	newChannel.On("Reject", ssh.ConnectionFailed, "failed to accept channel").Return(nil)

	// Create channel chan with one session channel
	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := NewSSHConnPair(zap.NewNop(), downstreamConn, upstreamConn, channelChan)

	// Track if serve completes
	done := make(chan struct{})

	go func() {
		connPair.serve()
		close(done)
	}()

	// Wait for serve to complete
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("serve() did not complete within timeout")
	}

	upstreamConn.AssertExpectations(t)
	newChannel.AssertExpectations(t)
}

func TestSSHConnPair_serve_MultipleChannels(t *testing.T) {
	t.Parallel()
	downstreamConn := &mockSSHConn{user: "downstream-user"}
	upstreamConn := &mockSSHConn{user: "upstream-user"}

	// Create multiple mock channels
	sessionChannel1 := newMockNewChannel("session")
	sessionChannel2 := newMockNewChannel("session")
	nonSessionChannel := newMockNewChannel("direct-tcpip")

	downstreamChannel1 := NewMockChannel()
	downstreamChannel2 := NewMockChannel()
	upstreamChannel1 := NewMockChannel()
	upstreamChannel2 := NewMockChannel()

	// Create request channels
	downstreamRequests1 := make(chan *ssh.Request)
	downstreamRequests2 := make(chan *ssh.Request)
	upstreamRequests1 := make(chan *ssh.Request)
	upstreamRequests2 := make(chan *ssh.Request)

	close(downstreamRequests1)
	close(downstreamRequests2)
	close(upstreamRequests1)
	close(upstreamRequests2)

	// Create mock channel pairs
	mockChannelPair1 := newMockChannelPair()
	mockChannelPair2 := newMockChannelPair()
	mockFactory := newMockChannelPairFactory(nil)

	// Set up expectations for session channels
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return(upstreamChannel1, (<-chan *ssh.Request)(upstreamRequests1), nil).Once()
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return(upstreamChannel2, (<-chan *ssh.Request)(upstreamRequests2), nil).Once()

	sessionChannel1.On("Accept").Return(downstreamChannel1, (<-chan *ssh.Request)(downstreamRequests1), nil)
	sessionChannel2.On("Accept").Return(downstreamChannel2, (<-chan *ssh.Request)(downstreamRequests2), nil)

	mockFactory.On("NewChannelPair", mock.Anything, "upstream-user", downstreamChannel1, (<-chan *ssh.Request)(downstreamRequests1), upstreamChannel1, (<-chan *ssh.Request)(upstreamRequests1)).Return(mockChannelPair1).Once()
	mockFactory.On("NewChannelPair", mock.Anything, "upstream-user", downstreamChannel2, (<-chan *ssh.Request)(downstreamRequests2), upstreamChannel2, (<-chan *ssh.Request)(upstreamRequests2)).Return(mockChannelPair2).Once()

	mockChannelPair1.On("serve").Return()
	mockChannelPair2.On("serve").Return()

	// Set up expectations for non-session channel (should be rejected)
	nonSessionChannel.On("Reject", ssh.UnknownChannelType, "unknown channel type").Return(nil)

	// Create channel chan with multiple channels
	channelChan := createMockChannelChan([]ssh.NewChannel{sessionChannel1, nonSessionChannel, sessionChannel2})

	connPair := &SSHConnPair{
		logger:                    zap.NewNop(),
		downstreamConn:            downstreamConn,
		upstreamConn:              upstreamConn,
		downstreamSSHChannelsChan: channelChan,
		channelPairFactory:        mockFactory,
	}

	// Run serve in a goroutine
	done := make(chan struct{})

	go func() {
		defer close(done)

		connPair.serve()
	}()

	// Wait for both channel pairs to be called
	select {
	case <-mockChannelPair1.serveCalled:
		// First channel pair called
	case <-time.After(1 * time.Second):
		t.Fatal("First channel pair serve was not called within timeout")
	}

	select {
	case <-mockChannelPair2.serveCalled:
		// Second channel pair called
	case <-time.After(1 * time.Second):
		t.Fatal("Second channel pair serve was not called within timeout")
	}

	// Wait for serve to complete
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("serve() did not complete within timeout")
	}

	// Verify expectations
	upstreamConn.AssertExpectations(t)
	sessionChannel1.AssertExpectations(t)
	sessionChannel2.AssertExpectations(t)
	nonSessionChannel.AssertExpectations(t)
	mockFactory.AssertExpectations(t)
	mockChannelPair1.AssertExpectations(t)
	mockChannelPair2.AssertExpectations(t)
}

func TestSSHConnPair_close(t *testing.T) {
	t.Parallel()
	downstreamConn := &mockSSHConn{}
	upstreamConn := &mockSSHConn{}

	// Set up expectations
	downstreamConn.On("Close").Return(nil)
	upstreamConn.On("Close").Return(nil)

	connPair := &SSHConnPair{
		logger:         zap.NewNop(),
		downstreamConn: downstreamConn,
		upstreamConn:   upstreamConn,
	}

	connPair.close()

	downstreamConn.AssertExpectations(t)
	upstreamConn.AssertExpectations(t)
}
