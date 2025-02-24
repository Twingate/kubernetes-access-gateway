package wsproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"k8s.io/apimachinery/pkg/util/remotecommand"
)

var (
	errFailedToWriteToBuf     = errors.New("failed to write to buffer")
	errFailedToParseWS        = errors.New("failed to parse websocket fragment")
	errFailedToParseResizeMsg = errors.New("failed to parse resize message")
	errFailedToWriteResizeMsg = errors.New("failed to write resize message")
	errFailedToWriteHeader    = errors.New("failed to write header")
	errFailedToWriteRecording = errors.New("failed to write recording")
)

func NewConn(c net.Conn, recorder Recorder, asciinemaHeader asciinemaHeader, sessionHasTerminal bool) net.Conn {
	return &conn{
		Conn:               c,
		readFirstResize:    make(chan struct{}, 1),
		recorder:           recorder,
		asciinemaHeader:    asciinemaHeader,
		sessionHasTerminal: sessionHasTerminal,
	}
}

// creating an asciinema recording of a kubernetes ssh session.
type conn struct {
	net.Conn
	recorder        Recorder        // asciinema recording
	asciinemaHeader asciinemaHeader // header for the asciinema recording

	// true if the kubernetes exec is a terminal session, such as 'kubectl exec /bin/bash'
	// false if not a terminal session, such as 'kubectl exec ls'
	sessionHasTerminal bool

	// Reading from downstream
	readMutex   sync.Mutex // non-parallel read
	readMessage *wsMessage // current websocket message that is being parsed
	readBuffer  bytes.Buffer
	// For asciinema recording we need to have the starting terminal size so
	// that we can create the asciinema cast header, which is the metadata at the start of the recording.
	// see: https://docs.asciinema.org/manual/asciicast/v2/
	// The kubernetes subprotocol will send a StreamResize event at the start of the
	// session and we will use this first event as the terminal size for the cast header.
	// Further StreamResize events will be treated as normal resize events for the asciinema recording.
	// Once we have the first StreamResize event from downstream we can then:
	// 1. write the cast header which begins the recording
	// 2. allow upstream data to be written downstream
	readFirstResize     chan struct{} // used to signal Write() that we have the first resize event
	readFirstResizeOnce sync.Once     // only use `readFirstResize` once, and close the channel after

	// Writing to downstream
	writeMutex   sync.Mutex // non-parallel write
	writeMessage *wsMessage // current websocket message that is being parsed
	writeBuffer  bytes.Buffer
	// used to block and wait for readFirstResize to be signalled, and write the cast header only once and begin recording
	writeStartRecordingOnce sync.Once
}

func (c *conn) Read(data []byte) (int, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	bytesRead, readErr := c.Conn.Read(data)
	if readErr != nil {
		// since this connection can be a hijacked connection from the HTTP server
		// we could be dealing with a tls.Conn or some other wrapper around net.Conn, which
		// can wrap io.EOF errors, so we need to check
		if errors.Is(readErr, io.EOF) {
			readErr = io.EOF
		}
	}

	// not enough data to proceed any further
	if bytesRead == 0 {
		return 0, readErr
	}

	// we are only interested in binary opcode (k8s)
	// or continuation opcode (subsequent fragments of a websocket message)
	if c.readMessage == nil && !isContinuationOrBinaryOpcode(data) {
		return bytesRead, readErr
	}

	// continue using c.readMessage if it's incomplete
	if c.readMessage == nil {
		c.readMessage = &wsMessage{}
	}

	// put data into buffer
	if _, err := c.readBuffer.Write(data[:bytesRead]); err != nil {
		return bytesRead, fmt.Errorf("%w: %w", errFailedToWriteToBuf, err)
	}

	// try to parse
	parsedBytes, err := c.readMessage.Parse(c.readBuffer.Bytes())
	if err != nil {
		return bytesRead, fmt.Errorf("%w: %w", errFailedToParseWS, err)
	} else if parsedBytes == 0 {
		// no error, but unable to parse - wants more data
		// we have the current bytes stored in the readBuffer and
		// we will add more on next Read() and try to Parse() again
		return bytesRead, readErr
	}

	// consume fragment from buffer
	c.readBuffer.Next(parsedBytes)

	if c.readMessage.isFinished {
		// resize event
		if c.readMessage.k8sStreamID == remotecommand.StreamResize {
			var resizeMessage resizeMsg
			if err = json.Unmarshal(c.readMessage.payload, &resizeMessage); err != nil {
				return bytesRead, fmt.Errorf("%w: %w", errFailedToParseResizeMsg, err)
			}

			// if it's the first resize, we save it for the asciinema cast header
			// otherwise we record it as a terminal resize event
			var firstResize bool

			c.readFirstResizeOnce.Do(func() {
				firstResize = true
			})

			if firstResize {
				// set the header terminal size and close the channel
				c.asciinemaHeader.Width = resizeMessage.Width
				c.asciinemaHeader.Height = resizeMessage.Height
				close(c.readFirstResize)
			} else if err := c.recorder.WriteResizeEvent(resizeMessage.Width, resizeMessage.Height); err != nil {
				return bytesRead, fmt.Errorf("%w: %w", errFailedToWriteResizeMsg, err)
			}
		}

		c.readMessage = nil
	}

	return bytesRead, readErr
}

func (c *conn) Write(data []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	// no data to proceed
	if len(data) == 0 {
		return 0, nil
	}

	// we are only interested in binary opcode (k8s)
	// or continuation opcode (subsequent fragments of a websocket message)
	if c.writeMessage == nil && !isContinuationOrBinaryOpcode(data) {
		return c.Conn.Write(data)
	}

	// continue using c.writeMessage if it's incomplete
	if c.writeMessage == nil {
		c.writeMessage = &wsMessage{}
	}

	// put data into buffer
	if _, err := c.writeBuffer.Write(data); err != nil {
		return 0, fmt.Errorf("%w: %w", errFailedToWriteToBuf, err)
	}

	// try to parse
	parsedBytes, err := c.writeMessage.Parse(c.writeBuffer.Bytes())

	if err != nil {
		return 0, fmt.Errorf("%w: %w", errFailedToParseWS, err)
	} else if parsedBytes == 0 {
		// no error, but unable to parse - wants more data
		// we have the current bytes stored in the writeBuffer and
		// we will add more on next Write() and try to Parse() again
		return len(data), nil
	}

	// write the fragment and return if the message isn't finished
	if !c.writeMessage.isFinished {
		_, writeErr := c.Conn.Write(c.writeBuffer.Bytes())
		c.writeBuffer.Next(parsedBytes)

		return len(data), writeErr
	}

	if c.writeMessage.k8sStreamID == remotecommand.StreamStdOut || c.writeMessage.k8sStreamID == remotecommand.StreamStdErr {
		// on first Write() we want to block and wait for the first resize event (if terminal) so that
		// we can record the asciinema header first and then continue the flow and recording
		var waitForFirstResize bool

		c.writeStartRecordingOnce.Do(func() {
			waitForFirstResize = c.sessionHasTerminal
		})

		// check if we need to wait
		if waitForFirstResize {
			<-c.readFirstResize // blocks waiting for Read() to unblock channel
		}

		// record the asciinema header first to start the recording
		if !c.recorder.IsStarted() {
			if err := c.recorder.WriteHeader(c.asciinemaHeader); err != nil {
				return 0, fmt.Errorf("%w: %w", errFailedToWriteHeader, err)
			}
		}

		// now we can write events
		if err := c.recorder.WriteOutputEvent(c.writeMessage.payload); err != nil {
			return 0, fmt.Errorf("%w: %w", errFailedToWriteRecording, err)
		}
	}

	c.writeMessage = nil

	// write the fragment
	_, writeErr := c.Conn.Write(c.writeBuffer.Bytes())
	// consume fragment from buffer now that we are done with it
	c.writeBuffer.Next(parsedBytes)

	return len(data), writeErr
}

func (c *conn) Close() error {
	c.readMutex.Lock()
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	defer c.readMutex.Unlock()
	c.recorder.Stop() // stop recording

	return c.Conn.Close()
}

// %x2 denotes a binary frame.
func isContinuationOrBinaryOpcode(b []byte) bool {
	return len(b) > 0 && (b[0]&0xf) == 0 || (b[0]&0xf) == 2
}
