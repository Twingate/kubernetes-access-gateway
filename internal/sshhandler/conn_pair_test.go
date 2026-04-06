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
func (m *mockChannelPairFactory) NewChannelPair(logger *zap.Logger, sshChannelCtx *sshChannelContext, sshUsername string, sourceChannel ssh.Channel, sourceRequests <-chan *ssh.Request, targetChannel ssh.Channel, targetRequests <-chan *ssh.Request) ChannelPair {
	args := m.Called(logger, sshChannelCtx, sshUsername, sourceChannel, sourceRequests, targetChannel, targetRequests)

	return args.Get(0).(ChannelPair)
}

var testSSHContext = &sshContext{
	id:            "test-session-id",
	username:      "testuser",
	clientVersion: "SSH-2.0-test",
	serverVersion: "SSH-2.0-upstream",
}

// setupConnWaitClose sets up Wait/Close expectations on a mockSSHConn so that serve()
// cross-close goroutines don't panic on unexpected calls.
func setupConnWaitClose(conn *mockSSHConn) {
	conn.On("Wait").Return(nil)
	conn.On("Close").Return(nil)
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
	upstreamConn := &mockSSHConn{user: "testuser"}

	setupConnWaitClose(downstreamConn)
	setupConnWaitClose(upstreamConn)

	// Create mock channels
	newChannel := newMockNewChannel("session")
	sourceChannel := NewMockChannel()
	targetChannel := NewMockChannel()

	// Create request channels
	sourceRequests := make(chan *ssh.Request)
	targetRequests := make(chan *ssh.Request)

	// Create mock channel pair
	mockChannelPair := newMockChannelPair()
	mockFactory := newMockChannelPairFactory(mockChannelPair)

	// Set up expectations
	newChannel.On("ExtraData").Return([]byte(nil))
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return(targetChannel, (<-chan *ssh.Request)(targetRequests), nil)
	newChannel.On("Accept").Return(sourceChannel, (<-chan *ssh.Request)(sourceRequests), nil)
	mockFactory.On("NewChannelPair", mock.Anything, mock.Anything, "testuser", sourceChannel, (<-chan *ssh.Request)(sourceRequests), targetChannel, (<-chan *ssh.Request)(targetRequests)).Return(mockChannelPair)
	mockChannelPair.On("serve").Return()

	// Create channel chan with one session channel
	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := &SSHConnPair{
		logger:                    zap.NewNop(),
		sshCtx:                    testSSHContext,
		downstreamConn:            downstreamConn,
		downstreamSSHChannelsChan: channelChan,
		downstreamRequestsChan:    closedRequestChan(),
		upstreamConn:              upstreamConn,
		upstreamSSHChannelsChan:   createMockChannelChan(nil),
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
	upstreamConn := &mockSSHConn{user: "testuser"}

	setupConnWaitClose(downstreamConn)
	setupConnWaitClose(upstreamConn)

	// Create mock channel with direct-tcpip type (port forwarding)
	extraData := []byte("extra-data")
	newChannel := newMockNewChannel("direct-tcpip")
	sourceChannel := NewMockChannel()
	targetChannel := NewMockChannel()

	// Create request channels
	sourceRequests := make(chan *ssh.Request)
	targetRequests := make(chan *ssh.Request)

	// Create mock channel pair
	mockChannelPair := newMockChannelPair()
	mockFactory := newMockChannelPairFactory(mockChannelPair)

	// Set up expectations - channel should be forwarded with original type and extra data
	newChannel.On("ExtraData").Return(extraData)
	upstreamConn.On("OpenChannel", "direct-tcpip", extraData).Return(targetChannel, (<-chan *ssh.Request)(targetRequests), nil)
	newChannel.On("Accept").Return(sourceChannel, (<-chan *ssh.Request)(sourceRequests), nil)
	mockFactory.On("NewChannelPair", mock.Anything, mock.Anything, "testuser", sourceChannel, (<-chan *ssh.Request)(sourceRequests), targetChannel, (<-chan *ssh.Request)(targetRequests)).Return(mockChannelPair)
	mockChannelPair.On("serve").Return()

	// Create channel chan with one direct-tcpip channel
	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := &SSHConnPair{
		logger:                    zap.NewNop(),
		sshCtx:                    testSSHContext,
		downstreamConn:            downstreamConn,
		downstreamSSHChannelsChan: channelChan,
		downstreamRequestsChan:    closedRequestChan(),
		upstreamConn:              upstreamConn,
		upstreamSSHChannelsChan:   createMockChannelChan(nil),
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

	setupConnWaitClose(downstreamConn)
	setupConnWaitClose(upstreamConn)

	// Create mock channels
	newChannel := newMockNewChannel("session")

	// Set up expectations - upstream fails to open channel
	newChannel.On("ExtraData").Return([]byte(nil))

	expectedErr := errors.New("upstream connection failed")
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return((*MockChannel)(nil), (<-chan *ssh.Request)(nil), expectedErr)
	newChannel.On("Reject", ssh.ConnectionFailed, "failed to open target channel").Return(nil)

	// Create channel chan with one session channel
	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := NewSSHConnPair(zap.NewNop(), testSSHContext, downstreamConn, channelChan, closedRequestChan(), upstreamConn, createMockChannelChan(nil), closedRequestChan())

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

	setupConnWaitClose(downstreamConn)
	setupConnWaitClose(upstreamConn)

	// Create mock channels
	newChannel := newMockNewChannel("session")
	targetChannel := NewMockChannel()

	// Create request channels
	targetRequests := make(chan *ssh.Request)
	close(targetRequests)

	// Set up expectations
	newChannel.On("ExtraData").Return([]byte(nil))
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return(targetChannel, (<-chan *ssh.Request)(targetRequests), nil)

	// Source accept fails
	expectedErr := errors.New("downstream accept failed")
	newChannel.On("Accept").Return((*MockChannel)(nil), (<-chan *ssh.Request)(nil), expectedErr)
	targetChannel.On("Close").Return(nil)

	// Create channel chan with one session channel
	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := NewSSHConnPair(zap.NewNop(), testSSHContext, downstreamConn, channelChan, closedRequestChan(), upstreamConn, createMockChannelChan(nil), closedRequestChan())

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
	targetChannel.AssertExpectations(t)
	newChannel.AssertExpectations(t)
}

func TestSSHConnPair_serve_MultipleChannels(t *testing.T) {
	downstreamConn := &mockSSHConn{user: "downstream-user"}
	upstreamConn := &mockSSHConn{user: "testuser"}

	setupConnWaitClose(downstreamConn)
	setupConnWaitClose(upstreamConn)

	// Create multiple mock channels: session + direct-tcpip + session
	sessionChannel1 := newMockNewChannel("session")
	directTCPIPChannel := newMockNewChannel("direct-tcpip")
	sessionChannel2 := newMockNewChannel("session")

	sourceChannel1 := NewMockChannel()
	sourceChannel2 := NewMockChannel()
	sourceChannel3 := NewMockChannel()
	targetChannel1 := NewMockChannel()
	targetChannel2 := NewMockChannel()
	targetChannel3 := NewMockChannel()

	// Create request channels
	sourceRequests1 := make(chan *ssh.Request)
	sourceRequests2 := make(chan *ssh.Request)
	sourceRequests3 := make(chan *ssh.Request)
	targetRequests1 := make(chan *ssh.Request)
	targetRequests2 := make(chan *ssh.Request)
	targetRequests3 := make(chan *ssh.Request)

	close(sourceRequests1)
	close(sourceRequests2)
	close(sourceRequests3)
	close(targetRequests1)
	close(targetRequests2)
	close(targetRequests3)

	// Create mock channel pairs
	mockChannelPair1 := newMockChannelPair()
	mockChannelPair2 := newMockChannelPair()
	mockChannelPair3 := newMockChannelPair()
	mockFactory := newMockChannelPairFactory(nil)

	// Set up expectations for session channels
	sessionChannel1.On("ExtraData").Return([]byte(nil))
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return(targetChannel1, (<-chan *ssh.Request)(targetRequests1), nil).Once()
	sessionChannel1.On("Accept").Return(sourceChannel1, (<-chan *ssh.Request)(sourceRequests1), nil)
	mockFactory.On("NewChannelPair", mock.Anything, mock.Anything, "testuser", sourceChannel1, (<-chan *ssh.Request)(sourceRequests1), targetChannel1, (<-chan *ssh.Request)(targetRequests1)).Return(mockChannelPair1).Once()
	mockChannelPair1.On("serve").Return()

	// Set up expectations for direct-tcpip channel (should be forwarded, not rejected)
	directTCPIPExtraData := []byte("direct-tcpip-data")
	directTCPIPChannel.On("ExtraData").Return(directTCPIPExtraData)
	upstreamConn.On("OpenChannel", "direct-tcpip", directTCPIPExtraData).Return(targetChannel2, (<-chan *ssh.Request)(targetRequests2), nil)
	directTCPIPChannel.On("Accept").Return(sourceChannel2, (<-chan *ssh.Request)(sourceRequests2), nil)
	mockFactory.On("NewChannelPair", mock.Anything, mock.Anything, "testuser", sourceChannel2, (<-chan *ssh.Request)(sourceRequests2), targetChannel2, (<-chan *ssh.Request)(targetRequests2)).Return(mockChannelPair2).Once()
	mockChannelPair2.On("serve").Return()

	// Set up expectations for second session channel
	sessionChannel2.On("ExtraData").Return([]byte(nil))
	upstreamConn.On("OpenChannel", "session", []byte(nil)).Return(targetChannel3, (<-chan *ssh.Request)(targetRequests3), nil).Once()
	sessionChannel2.On("Accept").Return(sourceChannel3, (<-chan *ssh.Request)(sourceRequests3), nil)
	mockFactory.On("NewChannelPair", mock.Anything, mock.Anything, "testuser", sourceChannel3, (<-chan *ssh.Request)(sourceRequests3), targetChannel3, (<-chan *ssh.Request)(targetRequests3)).Return(mockChannelPair3).Once()
	mockChannelPair3.On("serve").Return()

	// Create channel chan with multiple channels
	channelChan := createMockChannelChan([]ssh.NewChannel{sessionChannel1, directTCPIPChannel, sessionChannel2})

	connPair := &SSHConnPair{
		logger:                    zap.NewNop(),
		sshCtx:                    testSSHContext,
		downstreamConn:            downstreamConn,
		downstreamSSHChannelsChan: channelChan,
		downstreamRequestsChan:    closedRequestChan(),
		upstreamConn:              upstreamConn,
		upstreamSSHChannelsChan:   createMockChannelChan(nil),
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

func TestSSHConnPair_serve_ClosesOtherSideOnDisconnect(t *testing.T) {
	downstreamConn := &mockSSHConn{}
	upstreamConn := &mockSSHConn{}

	upstreamWait := make(chan struct{})

	// downstream.Wait() returns immediately (simulating disconnect)
	downstreamConn.On("Wait").Return(nil)
	downstreamConn.On("Close").Return(nil)

	// upstream.Wait() blocks until Close is called (simulating real SSH behavior)
	upstreamConn.On("Wait").Run(func(mock.Arguments) { <-upstreamWait }).Return(nil)
	upstreamConn.On("Close").Run(func(mock.Arguments) {
		select {
		case <-upstreamWait:
		default:
			close(upstreamWait)
		}
	}).Return(nil)

	connPair := &SSHConnPair{
		logger:                    zap.NewNop(),
		sshCtx:                    testSSHContext,
		downstreamConn:            downstreamConn,
		downstreamSSHChannelsChan: createMockChannelChan(nil),
		downstreamRequestsChan:    closedRequestChan(),
		upstreamConn:              upstreamConn,
		upstreamSSHChannelsChan:   createMockChannelChan(nil),
		upstreamRequestsChan:      closedRequestChan(),
		channelPairFactory:        &DefaultChannelPairFactory{},
	}

	// serve() should complete because:
	// 1. downstream.Wait() returns → upstream.Close() called → upstreamWait unblocks
	// 2. upstream.Wait() returns → downstream.Close() called
	done := make(chan struct{})

	go func() {
		connPair.serve()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("serve() did not complete within timeout — cross-close may not be working")
	}

	upstreamConn.AssertCalled(t, "Close")
	downstreamConn.AssertCalled(t, "Close")
}

func TestSSHConnPair_forwardChannels_RejectsDisallowedChannelType(t *testing.T) {
	downstreamConn := &mockSSHConn{user: "downstream-user"}
	upstreamConn := &mockSSHConn{user: "testuser"}

	setupConnWaitClose(downstreamConn)
	setupConnWaitClose(upstreamConn)

	// Create a "session" channel coming from upstream — in disallowedUpstreamChannelTypes
	newChannel := newMockNewChannel("session")
	newChannel.On("Reject", ssh.Prohibited, "channel type not allowed").Return(nil)

	channelChan := createMockChannelChan([]ssh.NewChannel{newChannel})

	connPair := &SSHConnPair{
		logger:                    zap.NewNop(),
		sshCtx:                    testSSHContext,
		downstreamConn:            downstreamConn,
		downstreamSSHChannelsChan: createMockChannelChan(nil),
		downstreamRequestsChan:    closedRequestChan(),
		upstreamConn:              upstreamConn,
		upstreamSSHChannelsChan:   channelChan,
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

func TestSSHConnPair_forwardGlobalRequests_ForwardsNonDeniedType(t *testing.T) {
	targetConn := &mockSSHConn{}

	// keepalive@openssh.com is not in any denylist and should be forwarded
	targetConn.On("SendRequest", "keepalive@openssh.com", false, []byte("payload")).Return(true, []byte(nil), nil)

	reqChan := make(chan *ssh.Request, 1)
	reqChan <- &ssh.Request{
		Type:      "keepalive@openssh.com",
		WantReply: false,
		Payload:   []byte("payload"),
	}

	close(reqChan)

	connPair := &SSHConnPair{logger: zap.NewNop(), sshCtx: testSSHContext}
	connPair.forwardGlobalRequests(reqChan, targetConn, disallowedUpstreamGlobalRequests, labelUpstream, labelDownstream)

	targetConn.AssertExpectations(t)
}

func TestSSHConnPair_forwardGlobalRequests_BlocksDeniedType(t *testing.T) {
	targetConn := &mockSSHConn{}

	// tcpip-forward is a client→server request and should be blocked from upstream
	reqChan := make(chan *ssh.Request, 1)
	reqChan <- &ssh.Request{
		Type:      "tcpip-forward",
		WantReply: false,
	}

	close(reqChan)

	connPair := &SSHConnPair{logger: zap.NewNop(), sshCtx: testSSHContext}
	connPair.forwardGlobalRequests(reqChan, targetConn, disallowedUpstreamGlobalRequests, labelUpstream, labelDownstream)

	// SendRequest should never be called for disallowed types
	targetConn.AssertNotCalled(t, "SendRequest")
}

func TestSSHConnPair_forwardGlobalRequests_ForwardsAllWhenNoDenyList(t *testing.T) {
	targetConn := &mockSSHConn{}

	// All requests should be forwarded when denylist is nil (downstream direction)
	targetConn.On("SendRequest", "tcpip-forward", false, []byte("payload")).Return(true, []byte(nil), nil)

	reqChan := make(chan *ssh.Request, 1)
	reqChan <- &ssh.Request{
		Type:      "tcpip-forward",
		WantReply: false,
		Payload:   []byte("payload"),
	}

	close(reqChan)

	connPair := &SSHConnPair{logger: zap.NewNop(), sshCtx: testSSHContext}
	connPair.forwardGlobalRequests(reqChan, targetConn, nil, labelDownstream, labelUpstream)

	targetConn.AssertExpectations(t)
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
