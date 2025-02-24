package wsproxy

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockConn struct {
	readData  []byte
	writeData *bytes.Buffer
	closed    bool
}

func (m *mockConn) Read(b []byte) (int, error) {
	if len(m.readData) == 0 {
		return 0, nil
	}

	n := copy(b, m.readData)
	m.readData = m.readData[n:]

	return n, nil
}

func (m *mockConn) Write(b []byte) (int, error) {
	if m.writeData == nil {
		m.writeData = new(bytes.Buffer)
	}

	return m.writeData.Write(b)
}

func (m *mockConn) Close() error {
	m.closed = true

	return nil
}

func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(_ time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(_ time.Time) error { return nil }

type mockRecorder struct {
	headerWritten bool
	header        asciinemaHeader
	events        [][]byte
	resizeEvents  []resizeMsg
	stopped       bool
}

func (m *mockRecorder) WriteHeader(h asciinemaHeader) error {
	m.header = h
	m.headerWritten = true

	return nil
}

func (m *mockRecorder) WriteOutputEvent(data []byte) error {
	m.events = append(m.events, data)

	return nil
}

func (m *mockRecorder) WriteResizeEvent(width, height int) error {
	m.resizeEvents = append(m.resizeEvents, resizeMsg{Width: width, Height: height})

	return nil
}

func (m *mockRecorder) Stop() {
	m.stopped = true
}

func (m *mockRecorder) IsStarted() bool {
	return m.headerWritten
}

func TestConn_Read(t *testing.T) {
	tests := []struct {
		name         string
		readInputs   [][]byte
		resizeWidth  int
		resizeHeight int
		expectResize bool
	}{
		{
			name:         "resize message",
			readInputs:   [][]byte{{0x82, 0x19, 0x4, 0x7b, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22, 0x3a, 0x34, 0x30, 0x2c, 0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3a, 0x38, 0x30, 0x7d}},
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
		{
			name:         "resize message, 2 reads",
			readInputs:   [][]byte{{0x2, 0x9, 0x4, 0x7b, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22}, {0x80, 0x11, 0x4, 0x3a, 0x34, 0x30, 0x2c, 0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3a, 0x38, 0x30, 0x7d}},
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
		{
			name:         "resize message, 3 reads and 2 fragments",
			readInputs:   [][]byte{{0x2, 0x9, 0x4, 0x7b, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22}, {0x80, 0x11, 0x4, 0x3a, 0x34, 0x30, 0x2c, 0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74}, {0x22, 0x3a, 0x38, 0x30, 0x7d}},
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
		{
			name:         "control message",
			readInputs:   [][]byte{{0x88, 0x0}},
			expectResize: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := &mockConn{}
			mr := &mockRecorder{}
			c := NewConn(mc, mr, asciinemaHeader{}, true).(*conn)

			for _, input := range tt.readInputs {
				mc.readData = append(mc.readData, input...)
				buf := make([]byte, len(input))

				n, err := c.Read(buf)
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}

				if n != len(input) {
					t.Errorf("Expected %d bytes read, got %d", len(input), n)
				}
			}

			// Check if first resize was processed
			if tt.expectResize {
				select {
				case <-c.readFirstResize:
					// Channel should be closed
				default:
					t.Error("Expected readFirstResize channel to be closed")
				}

				if c.asciinemaHeader.Width != tt.resizeWidth || c.asciinemaHeader.Height != tt.resizeHeight {
					t.Errorf("Expected header size %dx%d, got %dx%d",
						tt.resizeWidth, tt.resizeHeight,
						c.asciinemaHeader.Width, c.asciinemaHeader.Height)
				}
			}
		})
	}
}

func TestConn_Write(t *testing.T) {
	tests := []struct {
		name            string
		header          asciinemaHeader
		writeInputs     [][]byte
		expectedWSData  []byte
		expectedRecords [][]byte
		expectResize    bool
		hasTerminal     bool
	}{
		{
			name:            "single message, stdout",
			header:          asciinemaHeader{Version: 2, Width: 10, Height: 10},
			writeInputs:     [][]byte{{0x82, 0x8, 0x1, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}},
			expectedWSData:  []byte{0x82, 0x8, 0x1, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7},
			expectedRecords: [][]byte{{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}},
			expectResize:    true,
			hasTerminal:     true,
		},
		{
			name:            "single message, stderr",
			header:          asciinemaHeader{Version: 2, Width: 10, Height: 10},
			writeInputs:     [][]byte{{0x82, 0x8, 0x2, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}},
			expectedWSData:  []byte{0x82, 0x8, 0x2, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7},
			expectedRecords: [][]byte{{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}},
			expectResize:    true,
			hasTerminal:     true,
		},
		{
			name:            "single message, 2 writes",
			header:          asciinemaHeader{Version: 2, Width: 20, Height: 30},
			writeInputs:     [][]byte{{0x82, 0x8, 0x1, 0x1, 0x2}, {0x3, 0x4, 0x5, 0x6, 0x7}},
			expectedWSData:  []byte{0x82, 0x8, 0x1, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7},
			expectedRecords: [][]byte{{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}},
			expectResize:    true,
			hasTerminal:     true,
		},
		{
			name:            "single message, 3 writes and 2 fragments",
			header:          asciinemaHeader{Version: 2, Width: 20, Height: 30},
			writeInputs:     [][]byte{{0x2, 0x3, 0x1, 0x5, 0x5}, {0x80, 0x7, 0x1, 0x1, 0x2, 0x3, 0x4}, {0x5, 0x6}},
			expectedWSData:  []byte{0x2, 0x3, 0x1, 0x5, 0x5, 0x80, 0x7, 0x1, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
			expectedRecords: [][]byte{{0x5, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6}},
			expectResize:    true,
			hasTerminal:     true,
		},
		{
			name:            "single message 3 writes and 2 fragments, no terminal",
			header:          asciinemaHeader{Version: 2, Width: 20, Height: 30},
			writeInputs:     [][]byte{{0x2, 0x3, 0x1, 0x5, 0x5}, {0x80, 0x7, 0x1, 0x1, 0x2, 0x3, 0x4}, {0x5, 0x6}},
			expectedWSData:  []byte{0x2, 0x3, 0x1, 0x5, 0x5, 0x80, 0x7, 0x1, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
			expectedRecords: [][]byte{{0x5, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6}},
			expectResize:    false,
			hasTerminal:     false,
		},
		{
			name:           "control message",
			writeInputs:    [][]byte{{0x88, 0x0}},
			expectedWSData: []byte{0x88, 0x0},
			expectResize:   false,
			hasTerminal:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := &mockConn{}
			mr := &mockRecorder{}
			c := NewConn(mc, mr, tt.header, tt.hasTerminal).(*conn)

			if tt.expectResize && tt.hasTerminal {
				close(c.readFirstResize)
			}

			totalLength := 0
			for _, chunk := range tt.writeInputs {
				totalLength += len(chunk)
			}

			buf := make([]byte, 0, totalLength)
			for _, input := range tt.writeInputs {
				buf = append(buf, input...)

				bytesWritten, err := c.Write(buf)
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}

				buf = buf[bytesWritten:]
			}

			if !bytes.Equal(mc.writeData.Bytes(), tt.expectedWSData) {
				t.Errorf("Expected event data %v, got %v", tt.expectedWSData, mc.writeData.Bytes())
			}

			assert.Equal(t, tt.header.Version, mr.header.Version)
			assert.Equal(t, tt.header.Width, mr.header.Width)
			assert.Equal(t, tt.header.Height, mr.header.Height)

			assert.Equal(t, tt.expectedRecords, mr.events)
		})
	}
}

func TestConnRead_ErrorHandling(t *testing.T) {
	mc := &mockConn{}
	mr := &mockRecorder{}
	c := NewConn(mc, mr, asciinemaHeader{}, true).(*conn)

	malformedData := []byte{0x82, 0x0, 0x4, 0x7b, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22, 0x3a, 0x34, 0x30, 0x2c, 0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3a, 0x38, 0x30, 0x7d}
	mc.readData = append(mc.readData, malformedData...)

	buf := make([]byte, len(malformedData))

	_, err := c.Read(buf)
	if !errors.Is(err, errFailedToParseWS) {
		t.Errorf("Expected errFailedToParseWS, got %v", err)
	}
}

func TestConn_Close(t *testing.T) {
	mc := &mockConn{}
	mr := &mockRecorder{}
	c := NewConn(mc, mr, asciinemaHeader{}, true).(*conn)

	err := c.Close()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !mc.closed {
		t.Error("Expected underlying connection to be closed")
	}

	if !mr.stopped {
		t.Error("Expected recording to be stopped")
	}
}
