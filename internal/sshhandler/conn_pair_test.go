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
func (m *mockChannelPairFactory) NewChannelPair(logger *zap.Logger, upstreamSSHUsername string, downstreamChannel ssh.Channel, downstreamRequests <-chan *ssh.Request, upstreamChannel ssh.Channel, upstreamRequests <-chan *ssh.Request, waitToStart bool) ChannelPair {
	args := m.Called(logger, upstreamSSHUsername, downstreamChannel, downstreamRequests, upstreamChannel, upstreamRequests, waitToStart)

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

// Test helper to create a closed request channel.
func closedRequestChan() <-chan *ssh.Request {
	ch := make(chan *ssh.Request)
	close(ch)

	return ch
}

func TestSSHConnPair_serve_SessionChannelSuccess(t *testing.T) {
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
	newChannel.On("ExtraData").Return([]byte(nil))
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return(upstreamChannel, (<-chan *ssh.Request)(upstreamRequests), nil)
	newChannel.On("Accept").Return(downstreamChannel, (<-chan *ssh.Request)(downstreamRequests), nil)
	mockFactory.On("NewChannelPair", mock.Anything, "upstream-user", downstreamChannel, (<-chan *ssh.Request)(downstreamRequests), upstreamChannel, (<-chan *ssh.Request)(upstreamRequests), true).Return(mockChannelPair)
	mockChannelPair.On("serve").Return()

	// Create channel chan with one session channel
	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := &SSHConnPair{
		logger:                    zap.NewNop(),
		downstreamConn:            downstreamConn,
		upstreamConn:              upstreamConn,
		downstreamSSHChannelsChan: channelChan,
		upstreamSSHChannelsChan:   createMockChannelChan(nil),
		downstreamRequestsChan:    closedRequestChan(),
		upstreamRequestsChan:      closedRequestChan(),
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

func TestSSHConnPair_serve_DirectTCPIPChannelForwarded(t *testing.T) {
	downstreamConn := &mockSSHConn{user: "downstream-user"}
	upstreamConn := &mockSSHConn{user: "upstream-user"}

	// Create mock channel with direct-tcpip type (port forwarding)
	extraData := []byte("extra-data")
	newChannel := newMockNewChannel("direct-tcpip")
	downstreamChannel := NewMockChannel()
	upstreamChannel := NewMockChannel()

	// Create request channels
	downstreamRequests := make(chan *ssh.Request)
	upstreamRequests := make(chan *ssh.Request)

	// Create mock channel pair
	mockChannelPair := newMockChannelPair()
	mockFactory := newMockChannelPairFactory(mockChannelPair)

	// Set up expectations - channel should be forwarded with original type and extra data
	newChannel.On("ExtraData").Return(extraData)
	upstreamConn.On("OpenChannel", "direct-tcpip", extraData).Return(upstreamChannel, (<-chan *ssh.Request)(upstreamRequests), nil)
	newChannel.On("Accept").Return(downstreamChannel, (<-chan *ssh.Request)(downstreamRequests), nil)
	mockFactory.On("NewChannelPair", mock.Anything, "upstream-user", downstreamChannel, (<-chan *ssh.Request)(downstreamRequests), upstreamChannel, (<-chan *ssh.Request)(upstreamRequests), false).Return(mockChannelPair)
	mockChannelPair.On("serve").Return()

	// Create channel chan with one direct-tcpip channel
	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := &SSHConnPair{
		logger:                    zap.NewNop(),
		downstreamConn:            downstreamConn,
		upstreamConn:              upstreamConn,
		downstreamSSHChannelsChan: channelChan,
		upstreamSSHChannelsChan:   createMockChannelChan(nil),
		downstreamRequestsChan:    closedRequestChan(),
		upstreamRequestsChan:      closedRequestChan(),
		channelPairFactory:        mockFactory,
	}

	// Track if serve completes
	done := make(chan struct{})

	go func() {
		connPair.serve()
		close(done)
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

	newChannel.AssertExpectations(t)
	upstreamConn.AssertExpectations(t)
	mockFactory.AssertExpectations(t)
	mockChannelPair.AssertExpectations(t)
}

func TestSSHConnPair_serve_UpstreamOpenChannelFailure(t *testing.T) {
	downstreamConn := &mockSSHConn{}
	upstreamConn := &mockSSHConn{}

	// Create mock channels
	newChannel := newMockNewChannel("session")

	// Set up expectations - upstream fails to open channel
	newChannel.On("ExtraData").Return([]byte(nil))

	expectedErr := errors.New("upstream connection failed")
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return((*MockChannel)(nil), (<-chan *ssh.Request)(nil), expectedErr)
	newChannel.On("Reject", ssh.ConnectionFailed, "failed to create upstream session").Return(nil)

	// Create channel chan with one session channel
	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := NewSSHConnPair(zap.NewNop(), downstreamConn, channelChan, closedRequestChan(), upstreamConn, createMockChannelChan(nil), closedRequestChan())

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
	downstreamConn := &mockSSHConn{}
	upstreamConn := &mockSSHConn{}

	// Create mock channels
	newChannel := newMockNewChannel("session")
	upstreamChannel := NewMockChannel()

	// Create request channels
	upstreamRequests := make(chan *ssh.Request)
	close(upstreamRequests)

	// Set up expectations
	newChannel.On("ExtraData").Return([]byte(nil))
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return(upstreamChannel, (<-chan *ssh.Request)(upstreamRequests), nil)

	// Downstream accept fails
	expectedErr := errors.New("downstream accept failed")
	newChannel.On("Accept").Return((*MockChannel)(nil), (<-chan *ssh.Request)(nil), expectedErr)
	newChannel.On("Reject", ssh.ConnectionFailed, "failed to accept channel").Return(nil)

	// Create channel chan with one session channel
	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := NewSSHConnPair(zap.NewNop(), downstreamConn, channelChan, closedRequestChan(), upstreamConn, createMockChannelChan(nil), closedRequestChan())

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
	downstreamConn := &mockSSHConn{user: "downstream-user"}
	upstreamConn := &mockSSHConn{user: "upstream-user"}

	// Create multiple mock channels: session + direct-tcpip + session
	sessionChannel1 := newMockNewChannel("session")
	directTCPIPChannel := newMockNewChannel("direct-tcpip")
	sessionChannel2 := newMockNewChannel("session")

	downstreamChannel1 := NewMockChannel()
	downstreamChannel2 := NewMockChannel()
	downstreamChannel3 := NewMockChannel()
	upstreamChannel1 := NewMockChannel()
	upstreamChannel2 := NewMockChannel()
	upstreamChannel3 := NewMockChannel()

	// Create request channels
	downstreamRequests1 := make(chan *ssh.Request)
	downstreamRequests2 := make(chan *ssh.Request)
	downstreamRequests3 := make(chan *ssh.Request)
	upstreamRequests1 := make(chan *ssh.Request)
	upstreamRequests2 := make(chan *ssh.Request)
	upstreamRequests3 := make(chan *ssh.Request)

	close(downstreamRequests1)
	close(downstreamRequests2)
	close(downstreamRequests3)
	close(upstreamRequests1)
	close(upstreamRequests2)
	close(upstreamRequests3)

	// Create mock channel pairs
	mockChannelPair1 := newMockChannelPair()
	mockChannelPair2 := newMockChannelPair()
	mockChannelPair3 := newMockChannelPair()
	mockFactory := newMockChannelPairFactory(nil)

	// Set up expectations for session channels
	sessionChannel1.On("ExtraData").Return([]byte(nil))
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return(upstreamChannel1, (<-chan *ssh.Request)(upstreamRequests1), nil).Once()
	sessionChannel1.On("Accept").Return(downstreamChannel1, (<-chan *ssh.Request)(downstreamRequests1), nil)
	mockFactory.On("NewChannelPair", mock.Anything, "upstream-user", downstreamChannel1, (<-chan *ssh.Request)(downstreamRequests1), upstreamChannel1, (<-chan *ssh.Request)(upstreamRequests1), true).Return(mockChannelPair1).Once()
	mockChannelPair1.On("serve").Return()

	// Set up expectations for direct-tcpip channel (should be forwarded, not rejected)
	directTCPIPExtraData := []byte("direct-tcpip-data")
	directTCPIPChannel.On("ExtraData").Return(directTCPIPExtraData)
	upstreamConn.On("OpenChannel", "direct-tcpip", directTCPIPExtraData).Return(upstreamChannel2, (<-chan *ssh.Request)(upstreamRequests2), nil)
	directTCPIPChannel.On("Accept").Return(downstreamChannel2, (<-chan *ssh.Request)(downstreamRequests2), nil)
	mockFactory.On("NewChannelPair", mock.Anything, "upstream-user", downstreamChannel2, (<-chan *ssh.Request)(downstreamRequests2), upstreamChannel2, (<-chan *ssh.Request)(upstreamRequests2), false).Return(mockChannelPair2).Once()
	mockChannelPair2.On("serve").Return()

	// Set up expectations for second session channel
	sessionChannel2.On("ExtraData").Return([]byte(nil))
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return(upstreamChannel3, (<-chan *ssh.Request)(upstreamRequests3), nil).Once()
	sessionChannel2.On("Accept").Return(downstreamChannel3, (<-chan *ssh.Request)(downstreamRequests3), nil)
	mockFactory.On("NewChannelPair", mock.Anything, "upstream-user", downstreamChannel3, (<-chan *ssh.Request)(downstreamRequests3), upstreamChannel3, (<-chan *ssh.Request)(upstreamRequests3), true).Return(mockChannelPair3).Once()
	mockChannelPair3.On("serve").Return()

	// Create channel chan with multiple channels
	channelChan := createMockChannelChan([]ssh.NewChannel{sessionChannel1, directTCPIPChannel, sessionChannel2})

	connPair := &SSHConnPair{
		logger:                    zap.NewNop(),
		downstreamConn:            downstreamConn,
		upstreamConn:              upstreamConn,
		downstreamSSHChannelsChan: channelChan,
		upstreamSSHChannelsChan:   createMockChannelChan(nil),
		downstreamRequestsChan:    closedRequestChan(),
		upstreamRequestsChan:      closedRequestChan(),
		channelPairFactory:        mockFactory,
	}

	// Run serve in a goroutine
	done := make(chan struct{})

	go func() {
		defer close(done)

		connPair.serve()
	}()

	// Wait for all channel pairs to be called
	select {
	case <-mockChannelPair1.serveCalled:
	case <-time.After(1 * time.Second):
		t.Fatal("First channel pair serve was not called within timeout")
	}

	select {
	case <-mockChannelPair2.serveCalled:
	case <-time.After(1 * time.Second):
		t.Fatal("Second channel pair serve was not called within timeout")
	}

	select {
	case <-mockChannelPair3.serveCalled:
	case <-time.After(1 * time.Second):
		t.Fatal("Third channel pair serve was not called within timeout")
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
	directTCPIPChannel.AssertExpectations(t)
	mockFactory.AssertExpectations(t)
	mockChannelPair1.AssertExpectations(t)
	mockChannelPair2.AssertExpectations(t)
	mockChannelPair3.AssertExpectations(t)
}

func TestSSHConnPair_forwardChannels_RejectsDisallowedChannelType(t *testing.T) {
	downstreamConn := &mockSSHConn{user: "downstream-user"}
	upstreamConn := &mockSSHConn{user: "upstream-user"}

	// Create a "session" channel coming from upstream — not in allowedUpstreamChannelTypes
	newChannel := newMockNewChannel("session")
	newChannel.On("Reject", ssh.Prohibited, "channel type not allowed").Return(nil)

	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := &SSHConnPair{
		logger:                    zap.NewNop(),
		downstreamConn:            downstreamConn,
		upstreamConn:              upstreamConn,
		downstreamSSHChannelsChan: createMockChannelChan(nil),
		upstreamSSHChannelsChan:   channelChan,
		downstreamRequestsChan:    closedRequestChan(),
		upstreamRequestsChan:      closedRequestChan(),
		channelPairFactory:        &DefaultChannelPairFactory{},
	}

	done := make(chan struct{})

	go func() {
		connPair.serve()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("serve() did not complete within timeout")
	}

	// Verify the channel was rejected, not forwarded
	newChannel.AssertExpectations(t)
	upstreamConn.AssertNotCalled(t, "OpenChannel")
}

func TestSSHConnPair_forwardGlobalRequests_ForwardsAllowedType(t *testing.T) {
	targetConn := &mockSSHConn{}

	// tcpip-forward is allowed downstream -> upstream
	targetConn.On("SendRequest", "tcpip-forward", false, []byte("payload")).Return(true, []byte(nil), nil)

	reqChan := make(chan *ssh.Request, 1)
	reqChan <- &ssh.Request{
		Type:      "tcpip-forward",
		WantReply: false,
		Payload:   []byte("payload"),
	}

	close(reqChan)

	connPair := &SSHConnPair{logger: zap.NewNop()}
	connPair.forwardGlobalRequests(reqChan, targetConn, allowedDownstreamGlobalRequests, "downstream -> upstream")

	targetConn.AssertExpectations(t)
}

func TestSSHConnPair_forwardGlobalRequests_BlocksDisallowedType(t *testing.T) {
	targetConn := &mockSSHConn{}

	// "env" is not in any allowlist
	reqChan := make(chan *ssh.Request, 1)
	reqChan <- &ssh.Request{
		Type:      "env",
		WantReply: false,
	}

	close(reqChan)

	connPair := &SSHConnPair{logger: zap.NewNop()}
	connPair.forwardGlobalRequests(reqChan, targetConn, allowedUpstreamGlobalRequests, "upstream -> downstream")

	// SendRequest should never be called for disallowed types
	targetConn.AssertNotCalled(t, "SendRequest")
}

func TestSSHConnPair_close(t *testing.T) {
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
