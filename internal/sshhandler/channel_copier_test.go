// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type mockTapWriter struct {
	mock.Mock

	data []byte
	mu   sync.Mutex
}

func (m *mockTapWriter) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data = append(m.data, p...)
	args := m.Called(p)

	return args.Int(0), args.Error(1)
}

func (m *mockTapWriter) GetData() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]byte(nil), m.data...)
}

func TestChannelCopyPair_copy_BasicCopy(t *testing.T) {
	t.Parallel()
	src := NewMockChannel()
	dst := NewMockChannel()

	testData := []byte("test data1234")
	src.SetData(testData)

	eofTriggerCh := make(chan SSHRequestHandlerFlushTrigger, 1)
	channelClosedCh := make(chan struct{}, 1)

	dst.On("CloseWrite").Return(nil)
	dst.On("Close").Return(nil)

	copyPair := &ChannelCopyPair{
		logger:          zap.NewNop(),
		Src:             src,
		Dst:             dst,
		EOFTriggerCh:    eofTriggerCh,
		ChannelClosedCh: channelClosedCh,
	}

	// EOF from src
	src.TriggerEOF()

	// Handle EOF trigger
	eofCalled := false

	go func() {
		trigger := <-eofTriggerCh
		trigger.cb()

		eofCalled = true

		// Signal channel fully closed
		close(channelClosedCh)
	}()

	copyPair.copy()

	// Verify data was copied
	assert.Equal(t, testData, dst.GetWrittenData())
	assert.True(t, eofCalled)
	dst.AssertExpectations(t)
}

func TestChannelCopyPair_copy_WithTap(t *testing.T) {
	t.Parallel()
	src := NewMockChannel()
	dst := NewMockChannel()
	tap := &mockTapWriter{}

	testData := []byte("test data for tap")
	src.SetData(testData)

	tap.On("Write", testData).Return(len(testData), nil)

	eofTriggerCh := make(chan SSHRequestHandlerFlushTrigger, 1)
	channelClosedCh := make(chan struct{}, 1)

	dst.On("CloseWrite").Return(nil)
	dst.On("Close").Return(nil)

	copyPair := &ChannelCopyPair{
		logger:          zap.NewNop(),
		Src:             src,
		Dst:             dst,
		EOFTriggerCh:    eofTriggerCh,
		ChannelClosedCh: channelClosedCh,
		Tap:             tap,
	}

	// EOF from src
	src.TriggerEOF()

	// Handle EOF trigger
	eofCalled := false

	go func() {
		trigger := <-eofTriggerCh
		trigger.cb()

		eofCalled = true

		// Signal channel fully closed
		close(channelClosedCh)
	}()

	copyPair.copy()

	// Verify data was copied to both destination and tap
	assert.Equal(t, testData, dst.GetWrittenData())
	assert.Equal(t, testData, tap.GetData())
	assert.True(t, eofCalled)
	tap.AssertExpectations(t)
	dst.AssertExpectations(t)
}

func TestChannelCopyPair_copy_ShutdownTimeout(t *testing.T) {
	// NOTE: Cannot use t.Parallel() because this test modifies global timeout variables
	src := NewMockChannel()
	dst := NewMockChannel()

	// Set a small amount of data
	src.SetData([]byte("test"))

	eofTriggerCh := make(chan SSHRequestHandlerFlushTrigger, 1)
	channelClosedCh := make(chan struct{})

	dst.On("CloseWrite").Return(nil)
	dst.On("Close").Return(nil)

	// Temporarily reduce timeouts for testing
	originalEOFTimeout := channelEOFTimeout
	channelEOFTimeout = 50 * time.Millisecond
	originalChannelCloseTimeout := channelCloseTimeout
	channelCloseTimeout = 50 * time.Millisecond

	defer func() {
		channelEOFTimeout = originalEOFTimeout
		channelCloseTimeout = originalChannelCloseTimeout
	}()

	copyPair := &ChannelCopyPair{
		logger:          zap.NewNop(),
		Src:             src,
		Dst:             dst,
		EOFTriggerCh:    eofTriggerCh,
		ChannelClosedCh: channelClosedCh,
	}

	// EOF from src
	// But no EOF trigger or closing of the channel
	src.TriggerEOF()

	start := time.Now()

	copyPair.copy()

	elapsed := time.Since(start)

	// Should have timed out after approximately the timeout duration
	assert.GreaterOrEqual(t, elapsed, 50*time.Millisecond)
	assert.Less(t, elapsed, 150*time.Millisecond) // Allow some margin

	dst.AssertExpectations(t)
}

func TestBidirectionalCopier_start(t *testing.T) {
	t.Parallel()
	// Create mock channels for both directions
	downstreamSrc := NewMockChannel()
	downstreamDst := NewMockChannel()
	upstreamSrc := NewMockChannel()
	upstreamDst := NewMockChannel()

	// Set up test data
	downstreamData := []byte("downstream data")
	upstreamData := []byte("upstream data")

	downstreamSrc.SetData(downstreamData)
	upstreamSrc.SetData(upstreamData)

	// Set up channels
	downstreamEOFTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)
	downstreamChannelClosed := make(chan struct{}, 1)
	upstreamEOFTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)
	upstreamChannelClosed := make(chan struct{}, 1)

	// Mock expectations
	downstreamDst.On("CloseWrite").Return(nil)
	downstreamDst.On("Close").Return(nil)
	upstreamDst.On("CloseWrite").Return(nil)
	upstreamDst.On("Close").Return(nil)

	copier := &BidirectionalCopier{
		logger: zap.NewNop(),
		DownstreamToUpstream: ChannelCopyPair{
			logger:          zap.NewNop(),
			Src:             downstreamSrc,
			Dst:             downstreamDst,
			EOFTriggerCh:    downstreamEOFTrigger,
			ChannelClosedCh: downstreamChannelClosed,
		},
		UpstreamToDownstream: ChannelCopyPair{
			logger:          zap.NewNop(),
			Src:             upstreamSrc,
			Dst:             upstreamDst,
			EOFTriggerCh:    upstreamEOFTrigger,
			ChannelClosedCh: upstreamChannelClosed,
		},
	}

	// Initiate shutdown from downstream EOF
	downstreamSrc.TriggerEOF()

	// Handle EOF trigger from downstream
	downstreamEOFCalled := false

	go func() {
		trigger := <-downstreamEOFTrigger
		trigger.cb()

		downstreamEOFCalled = true

		// Downstream should have done CloseWrite() at this point, and upstream
		// will receive SSH_MSG_CHANNEL_EOF, so simulate this by
		// starting EOF trigger for upstream
		upstreamSrc.TriggerEOF()

		// Now downstream can fully close
		close(downstreamChannelClosed)
	}()

	// Handle EOF trigger from upstream
	upstreamEOFCalled := false

	go func() {
		trigger := <-upstreamEOFTrigger
		trigger.cb()

		upstreamEOFCalled = true

		// Now upstream can fully close after receiving SSH_MSG_CHANNEL_EOF
		close(upstreamChannelClosed)
	}()

	// Mark time start
	start := time.Now()
	copier.start()
	elapsed := time.Since(start)

	// EOF triggers should have been called
	assert.True(t, downstreamEOFCalled)
	assert.True(t, upstreamEOFCalled)

	// Should complete quickly
	assert.Less(t, elapsed, 1*time.Second)

	// Verify data was copied in both directions
	assert.Equal(t, downstreamData, downstreamDst.GetWrittenData())
	assert.Equal(t, upstreamData, upstreamDst.GetWrittenData())

	downstreamDst.AssertExpectations(t)
	upstreamDst.AssertExpectations(t)
}
