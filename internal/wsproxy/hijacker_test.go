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

func mockNewConn(conn net.Conn, _ Recorder, _ asciinemaHeader, _ bool) net.Conn {
	return conn
}

func mockNewRecorder() *AsciinemaRecorder {
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

	if hijacker == nil {
		t.Fatal("Expected non-nil hijacker")
	}

	if hijacker.ResponseWriter != w {
		t.Errorf("Expected ResponseWriter to be %v, got %v", w, hijacker.ResponseWriter)
	}

	if hijacker.request != req {
		t.Errorf("Expected request to be %v, got %v", req, hijacker.request)
	}

	if hijacker.user != user {
		t.Errorf("Expected user to be %s, got %s", user, hijacker.user)
	}
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

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if conn != mockConn {
		t.Errorf("Expected conn to be %v, got %v", mockConn, conn)
	}

	if rw != mockRW {
		t.Errorf("Expected rw to be %v, got %v", mockRW, rw)
	}
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

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !errors.Is(err, errFailedToHijack) {
		t.Errorf("Expected error to wrap errFailedToHijack, got: %v", err)
	}
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

	if conn != mockConn {
		t.Errorf("Expected conn to be %v, got %v", mockConn, conn)
	}
}

func TestHijacker_AsciinemaHeaderCreation(t *testing.T) {
	var capturedHeader asciinemaHeader

	var capturedTty bool

	newConn := func(conn net.Conn, _ Recorder, header asciinemaHeader, isTty bool) net.Conn {
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

	if capturedHeader.Version != 2 {
		t.Errorf("Expected Version to be 2, got %d", capturedHeader.Version)
	}

	if capturedHeader.User != "testuser" {
		t.Errorf("Expected User to be 'testuser', got %s", capturedHeader.User)
	}

	if capturedHeader.Command != "bash" {
		t.Errorf("Expected Command to be 'bash', got %s", capturedHeader.Command)
	}

	if capturedHeader.K8sMetadata == nil {
		t.Fatal("Expected K8sMetadata to be non-nil")
	}

	if capturedHeader.K8sMetadata.PodName != "test-pod" {
		t.Errorf("Expected PodName to be 'test-pod', got %s", capturedHeader.K8sMetadata.PodName)
	}

	if capturedHeader.K8sMetadata.Namespace != "default" {
		t.Errorf("Expected Namespace to be 'default', got %s", capturedHeader.K8sMetadata.Namespace)
	}

	if capturedHeader.K8sMetadata.Container != "test-container" {
		t.Errorf("Expected Container to be 'test-container', got %s", capturedHeader.K8sMetadata.Container)
	}

	if !capturedTty {
		t.Errorf("Expected TTY flag to be true")
	}
}
