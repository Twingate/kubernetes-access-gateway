// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package wsproxy

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type mockHijackerResponseWriter struct {
	httptest.ResponseRecorder

	conn net.Conn
	rw   *bufio.ReadWriter
	err  error
}

func (m *mockHijackerResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, m.rw, m.err
}

type mockHijackerConn struct {
	net.Conn

	writeData []byte
}

func (m *mockHijackerConn) Read(_ []byte) (n int, err error) {
	return 0, nil
}

func (m *mockHijackerConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)

	return len(b), nil
}

func (m *mockHijackerConn) Close() error {
	return nil
}

func (m *mockHijackerConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

func (m *mockHijackerConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090}
}

func (m *mockHijackerConn) SetDeadline(_ time.Time) error {
	return nil
}

func (m *mockHijackerConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (m *mockHijackerConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func mockNewConn(conn net.Conn, _ Recorder, _ asciicastHeader, _ bool) net.Conn {
	return conn
}

func mockNewRecorder() *AsciicastRecorder {
	return NewRecorder(zap.NewNop())
}

func TestHijacker_New(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	user := "testuser"

	recorderFactory := func() Recorder {
		return mockNewRecorder()
	}
	hijacker := NewHijacker(req, w, user, recorderFactory, mockNewConn)

	assert.NotNil(t, hijacker)
	assert.Equal(t, w, hijacker.ResponseWriter)
	assert.Equal(t, req, hijacker.request)
	assert.Equal(t, user, hijacker.user)
}

func TestHijacker_Hijack_Success(t *testing.T) {
	mockConn := &mockHijackerConn{}
	mockRW := bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(nil))
	mockResp := &mockHijackerResponseWriter{
		conn: mockConn,
		rw:   mockRW,
		err:  nil,
	}

	req := httptest.NewRequest(http.MethodGet, "/namespaces/default/pods/test-pod/exec?container=test-container&command=bash&tty=true", nil)

	recorderFactory := func() Recorder {
		return mockNewRecorder()
	}
	hijacker := NewHijacker(req, mockResp, "testuser", recorderFactory, mockNewConn)

	conn, rw, err := hijacker.Hijack()

	require.NoError(t, err)
	assert.Equal(t, mockConn, conn)
	assert.Equal(t, mockRW, rw)
}

func TestHijacker_Hijack_Failure(t *testing.T) {
	mockResp := &mockHijackerResponseWriter{
		conn: nil,
		rw:   nil,
		err:  errors.New("hijack error"),
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	recorderFactory := func() Recorder {
		return mockNewRecorder()
	}
	hijacker := NewHijacker(req, mockResp, "testuser", recorderFactory, mockNewConn)

	_, _, err := hijacker.Hijack()

	assert.ErrorIs(t, err, errFailedToHijack)
}

func TestHijacker_StartRecorder(t *testing.T) {
	u, _ := url.Parse("/namespaces/default/pods/test-pod/exec?container=test-container&command=bash&tty=true")
	req := &http.Request{
		URL: u,
	}

	recorderFactory := func() Recorder {
		return mockNewRecorder()
	}
	hijacker := &WsHijacker{
		request:     req,
		user:        "testuser",
		newRecorder: recorderFactory,
		newConn:     mockNewConn,
	}

	mockConn := &mockHijackerConn{}
	conn := hijacker.startRecording(mockConn)

	assert.Equal(t, mockConn, conn)
}

func TestHijacker_AsciicastHeaderCreation(t *testing.T) {
	var capturedHeader asciicastHeader

	var capturedTty bool

	newConn := func(conn net.Conn, _ Recorder, header asciicastHeader, isTty bool) net.Conn {
		capturedHeader = header
		capturedTty = isTty

		return conn
	}

	mockConn := &mockHijackerConn{}

	u, _ := url.Parse("/namespaces/default/pods/test-pod/exec?container=test-container&command=bash&tty=true")
	req := &http.Request{
		URL: u,
	}

	req.SetPathValue("namespace", "default")
	req.SetPathValue("pod", "test-pod")

	recorderFactory := func() Recorder {
		return mockNewRecorder()
	}
	hijacker := &WsHijacker{
		request:     req,
		user:        "testuser",
		newRecorder: recorderFactory,
		newConn:     newConn,
	}

	hijacker.startRecording(mockConn)

	assert.Equal(t, 2, capturedHeader.Version)
	assert.Equal(t, "testuser", capturedHeader.User)
	assert.Equal(t, "bash", capturedHeader.Command)
	assert.NotEmpty(t, capturedHeader.K8sMetadata)
	assert.Equal(t, "test-pod", capturedHeader.K8sMetadata.PodName)
	assert.Equal(t, "default", capturedHeader.K8sMetadata.Namespace)
	assert.Equal(t, "test-container", capturedHeader.K8sMetadata.Container)
	assert.True(t, capturedTty)
}
