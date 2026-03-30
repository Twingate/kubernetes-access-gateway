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
	// Create mock channels for both directions
	sourceSrc := NewMockChannel()
	sourceDst := NewMockChannel()
	targetSrc := NewMockChannel()
	targetDst := NewMockChannel()

	// Set up test data
	sourceData := []byte("source data")
	targetData := []byte("target data")

	sourceSrc.SetData(sourceData)
	targetSrc.SetData(targetData)

	// Set up channels
	sourceEOFTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)
	sourceChannelClosed := make(chan struct{}, 1)
	targetEOFTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)
	targetChannelClosed := make(chan struct{}, 1)

	// Mock expectations
	sourceDst.On("CloseWrite").Return(nil)
	sourceDst.On("Close").Return(nil)
	targetDst.On("CloseWrite").Return(nil)
	targetDst.On("Close").Return(nil)

	copier := &BidirectionalCopier{
		logger: zap.NewNop(),
		SourceToTarget: ChannelCopyPair{
			logger:          zap.NewNop(),
			Src:             sourceSrc,
			Dst:             sourceDst,
			EOFTriggerCh:    sourceEOFTrigger,
			ChannelClosedCh: sourceChannelClosed,
		},
		TargetToSource: ChannelCopyPair{
			logger:          zap.NewNop(),
			Src:             targetSrc,
			Dst:             targetDst,
			EOFTriggerCh:    targetEOFTrigger,
			ChannelClosedCh: targetChannelClosed,
		},
	}

	// Initiate shutdown from source EOF
	sourceSrc.TriggerEOF()

	// Handle EOF trigger from source
	sourceEOFCalled := false

	go func() {
		trigger := <-sourceEOFTrigger
		trigger.cb()

		sourceEOFCalled = true

		// Source should have done CloseWrite() at this point, and target
		// will receive SSH_MSG_CHANNEL_EOF, so simulate this by
		// starting EOF trigger for target
		targetSrc.TriggerEOF()

		// Now source can fully close
		close(sourceChannelClosed)
	}()

	// Handle EOF trigger from target
	targetEOFCalled := false

	go func() {
		trigger := <-targetEOFTrigger
		trigger.cb()

		targetEOFCalled = true

		// Now target can fully close after receiving SSH_MSG_CHANNEL_EOF
		close(targetChannelClosed)
	}()

	// Mark time start
	start := time.Now()
	copier.start()
	elapsed := time.Since(start)

	// EOF triggers should have been called
	assert.True(t, sourceEOFCalled)
	assert.True(t, targetEOFCalled)

	// Should complete quickly
	assert.Less(t, elapsed, 1*time.Second)

	// Verify data was copied in both directions
	assert.Equal(t, sourceData, sourceDst.GetWrittenData())
	assert.Equal(t, targetData, targetDst.GetWrittenData())

	sourceDst.AssertExpectations(t)
	targetDst.AssertExpectations(t)
}
