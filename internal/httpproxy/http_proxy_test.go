package httpproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8sgateway/internal/connect"
	"k8sgateway/internal/log"
	"k8sgateway/internal/token"
)

type mockConn struct {
	net.Conn
	isClosed atomic.Bool
}

func (m *mockConn) Close() error {
	m.isClosed.Store(true)

	return nil
}

func (m *mockConn) IsClosed() bool {
	return m.isClosed.Load()
}

func TestNewProxyConn(t *testing.T) {
	conn := &mockConn{}
	claims := &token.GATClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(50 * time.Millisecond)),
		},
	}

	proxyConn := NewProxyConn(conn, claims)

	assert.NotNil(t, proxyConn)
	assert.Equal(t, claims, proxyConn.claims)
	assert.Equal(t, conn, proxyConn.Conn)

	// Wait for timer to happen, the connection should be closed
	time.Sleep(100 * time.Millisecond)
	assert.True(t, conn.IsClosed())
}

func TestProxyConn_Close(t *testing.T) {
	conn := &mockConn{}
	timer := time.NewTimer(0 * time.Millisecond)
	proxyConn := &ProxyConn{
		Conn:  conn,
		timer: timer,
	}

	_ = proxyConn.Close()

	assert.True(t, conn.IsClosed())

	// Verify that the timer was stopped
	select {
	case <-timer.C:
		assert.Fail(t, "Timer should have been stopped")
	default:
	}
}

func TestTruncateBody(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "Empty body",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "Short body",
			input:    []byte("This is a short body"),
			expected: "This is a short body",
		},
		{
			name:     "Exactly max size body",
			input:    bytes.Repeat([]byte("a"), bodyLogMaxSize),
			expected: string(bytes.Repeat([]byte("a"), bodyLogMaxSize)),
		},
		{
			name:     "Body longer than max size",
			input:    bytes.Repeat([]byte("a"), bodyLogMaxSize+50),
			expected: string(bytes.Repeat([]byte("a"), bodyLogMaxSizeWithSuffix)) + bodyLogTruncationSuffix,
		},
		{
			name:     "Unicode body truncation",
			input:    bytes.Repeat([]byte("こんにちは世界"), bodyLogMaxSize),
			expected: string(bytes.Repeat([]byte("こんにちは世界"), bodyLogMaxSize)[:bodyLogMaxSizeWithSuffix]) + bodyLogTruncationSuffix,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := truncateBody(tc.input)

			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}

			// check for overrun
			if len(result) > bodyLogMaxSize {
				t.Errorf("Truncated body exceeds max size. Length: %d, Max: %d",
					len(result), bodyLogMaxSize)
			}
		})
	}
}

func TestResponseLogger(t *testing.T) {
	recorder := httptest.NewRecorder()
	buffer := &bytes.Buffer{}
	logger := &responseLogger{
		ResponseWriter: recorder,
		body:           buffer,
	}

	t.Run("WriteHeader", func(t *testing.T) {
		testStatusCode := http.StatusBadRequest
		logger.WriteHeader(testStatusCode)
		assert.Equal(t, testStatusCode, logger.statusCode, "Status code not set correctly")
		assert.NotNil(t, logger.headers, "Headers should be cloned")
	})

	t.Run("Write", func(t *testing.T) {
		testData := []byte("hello!!!")
		n, err := logger.Write(testData)

		require.NoError(t, err, "Write should not return an error")
		assert.Equal(t, len(testData), n, "Number of bytes written should match input")
		assert.Equal(t, testData, logger.body.Bytes(), "Body buffer should contain written data")
	})

	t.Run("Write and WriteHeader combined", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		buffer := &bytes.Buffer{}
		logger := &responseLogger{
			ResponseWriter: recorder,
			body:           buffer,
		}

		testStatusCode := http.StatusOK
		testData := []byte("test response")

		logger.WriteHeader(testStatusCode)
		n, err := logger.Write(testData)

		require.NoError(t, err, "Write should not return an error")
		assert.Equal(t, testStatusCode, logger.statusCode, "Status code should be set correctly")
		assert.Equal(t, len(testData), n, "Number of bytes written should match input")
		assert.Equal(t, testData, logger.body.Bytes(), "Body buffer should contain written data")
		assert.Equal(t, recorder.Body.Bytes(), testData, "Underlying ResponseWriter should receive data")
	})
}

type mockValidator struct {
	shouldFail       bool
	ProxyAuth        string
	TokenSig         string
	apiServerAddress string
}

func (m *mockValidator) ParseConnect(req *http.Request, _ []byte) (claims *token.GATClaims, response string, err error) {
	if m.shouldFail {
		return nil, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", errors.New("failed to validate token")
	}

	claims = &token.GATClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
		User: token.User{
			ID:       "user-1",
			Username: "user@acme.com",
			Groups:   []string{"Everyone", "Engineering"},
		},
		Resource: token.Resource{ID: "resource-1", Address: m.apiServerAddress},
	}
	m.ProxyAuth = req.Header.Get(connect.AuthHeaderKey)
	m.TokenSig = req.Header.Get(connect.AuthSignatureHeaderKey)

	return claims, "HTTP/1.1 200 Connection Established\r\n\r\n", nil
}

func startMockListener(t *testing.T) (net.Listener, string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := listener.Addr().String()

	return listener, addr
}

func TestTCPListener_Accept_BadRequest(t *testing.T) {
	log.InitializeLogger("k8sproxytest", false)

	listener, addr := startMockListener(t)
	defer listener.Close()

	// make proxy TLS
	serverCert, _ := tls.LoadX509KeyPair("../../test/data/proxy_server.crt", "../../test/data/proxy_server.key")

	proxyTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	// mock CONNECT validator
	mockValidator := &mockValidator{
		shouldFail: false,
	}

	tcpListener := &tcpListener{
		Listener:         listener,
		TLSConfig:        proxyTLSConfig,
		ConnectValidator: mockValidator,
	}

	// make client TLS
	caCert, _ := os.ReadFile("../../test/data/proxy_server.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientTLSConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
	}

	done := make(chan struct{})
	go func() {
		// open TCP connection
		conn, err := net.Dial("tcp", addr)
		assert.NoError(t, err)
		defer conn.Close()

		// establish TLS (as downstream proxy)
		proxyTLSConn := tls.Client(conn, clientTLSConfig)
		if err := proxyTLSConn.Handshake(); err != nil {
			done <- struct{}{}

			return
		}

		// send a malformed request
		fmt.Fprintf(proxyTLSConn, "invalid-request\r\n\r\n")

		resp, err := bufio.NewReader(proxyTLSConn).ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 400 Bad Request\r\n", resp)

		done <- struct{}{}
	}()

	conn, err := tcpListener.Accept()
	require.NoError(t, err)
	assert.NotNil(t, conn)

	<-done
}

func TestTCPListener_Accept_Healthcheck(t *testing.T) {
	log.InitializeLogger("k8sproxytest", false)

	listener, addr := startMockListener(t)
	defer listener.Close()

	// make proxy TLS
	serverCert, _ := tls.LoadX509KeyPair("../../test/data/proxy_server.crt", "../../test/data/proxy_server.key")

	proxyTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	tcpListener := &tcpListener{
		Listener:  listener,
		TLSConfig: proxyTLSConfig,
	}

	// make client TLS
	caCert, _ := os.ReadFile("../../test/data/proxy_server.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientTLSConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
	}

	done := make(chan struct{})
	go func() {
		// open TCP connection
		conn, err := net.Dial("tcp", addr)
		assert.NoError(t, err)
		defer conn.Close()

		// establish TLS (as downstream proxy)
		proxyTLSConn := tls.Client(conn, clientTLSConfig)
		if err := proxyTLSConn.Handshake(); err != nil {
			done <- struct{}{}

			return
		}

		// send a healthcheck request
		fmt.Fprintf(proxyTLSConn, "GET /healthz HTTP/1.1\r\n\r\n")

		resp, err := bufio.NewReader(proxyTLSConn).ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 200 OK\r\n", resp)

		done <- struct{}{}
	}()

	conn, err := tcpListener.Accept()
	require.NoError(t, err)
	assert.NotNil(t, conn)

	<-done
}

func TestTCPListener_Accept_ValidConnectRequest(t *testing.T) {
	log.InitializeLogger("k8sproxytest", false)

	listener, addr := startMockListener(t)
	defer listener.Close()

	// make proxy TLS
	serverCert, _ := tls.LoadX509KeyPair("../../test/data/proxy_server.crt", "../../test/data/proxy_server.key")

	proxyTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	// mock CONNECT validator
	mockValidator := &mockValidator{
		shouldFail: false,
	}

	tcpListener := &tcpListener{
		Listener:         listener,
		TLSConfig:        proxyTLSConfig,
		ConnectValidator: mockValidator,
	}

	// make client TLS
	caCert, _ := os.ReadFile("../../test/data/proxy_server.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientTLSConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
	}

	done := make(chan struct{})
	go func() {
		// open TCP connection
		conn, err := net.Dial("tcp", addr)
		assert.NoError(t, err)
		defer conn.Close()

		// establish TLS (as downstream proxy)
		proxyTLSConn := tls.Client(conn, clientTLSConfig)
		if err := proxyTLSConn.Handshake(); err != nil {
			done <- struct{}{}

			return
		}

		// send a valid CONNECT request
		fmt.Fprintf(proxyTLSConn, "CONNECT example.com:443 HTTP/1.1\r\n%s: gat_token\r\n%s: auth_sig\r\n\r\n",
			connect.AuthHeaderKey, connect.AuthSignatureHeaderKey)

		// expect 200 Connection Established back
		resp, err := bufio.NewReader(proxyTLSConn).ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 200 Connection Established\r\n", resp)

		// establish second TLS (as downstream client)
		clientTLSConn := tls.Client(proxyTLSConn, clientTLSConfig)
		if err := clientTLSConn.Handshake(); err != nil {
			done <- struct{}{}

			return
		}

		done <- struct{}{}
	}()

	conn, err := tcpListener.Accept()
	require.NoError(t, err)
	assert.NotNil(t, conn)

	proxyConn, ok := conn.(*ProxyConn)
	assert.True(t, ok)
	assert.Equal(t, "user@acme.com", proxyConn.claims.User.Username)
	assert.ElementsMatch(t, []string{"Everyone", "Engineering"}, proxyConn.claims.User.Groups)
	assert.Equal(t, "gat_token", mockValidator.ProxyAuth)
	assert.Equal(t, "auth_sig", mockValidator.TokenSig)

	<-done
}

func TestTCPListener_Accept_FailedValidation(t *testing.T) {
	log.InitializeLogger("k8sproxytest", false)

	listener, addr := startMockListener(t)
	defer listener.Close()

	// make proxy TLS
	serverCert, _ := tls.LoadX509KeyPair("../../test/data/proxy_server.crt", "../../test/data/proxy_server.key")

	proxyTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	// mock CONNECT validator
	mockValidator := &mockValidator{
		shouldFail: true,
	}

	tcpListener := &tcpListener{
		Listener:         listener,
		TLSConfig:        proxyTLSConfig,
		ConnectValidator: mockValidator,
	}

	// make client TLS
	caCert, _ := os.ReadFile("../../test/data/proxy_server.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientTLSConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
	}

	done := make(chan struct{})
	go func() {
		// open TCP connection
		conn, err := net.Dial("tcp", addr)
		assert.NoError(t, err)
		defer conn.Close()

		// establish TLS (as downstream proxy)
		proxyTLSConn := tls.Client(conn, clientTLSConfig)
		if err := proxyTLSConn.Handshake(); err != nil {
			done <- struct{}{}

			return
		}

		fmt.Fprintf(proxyTLSConn, "CONNECT example.com:443 HTTP/1.1\r\n%s: bad_token\r\n%s: auth_sig\r\n\r\n",
			connect.AuthHeaderKey, connect.AuthSignatureHeaderKey)

		resp, err := bufio.NewReader(proxyTLSConn).ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 407 Proxy Authentication Required\r\n", resp)

		done <- struct{}{}
	}()

	conn, err := tcpListener.Accept()
	require.NoError(t, err)
	assert.NotNil(t, conn)

	<-done
}

func TestProxy_ForwardRequest(t *testing.T) {
	log.InitializeLogger("k8sproxytest", false)

	// create mock API server (upstream)
	apiServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// proxy should provide the correct 'Impersonate-User' header
		assert.Equal(t, "user@acme.com", r.Header.Get("Impersonate-User"))
		// proxy should provide the correct 'Impersonate-Groups' header
		assert.Equal(t, []string{"Everyone", "Engineering"}, r.Header.Values("Impersonate-Group"))
		// proxy should provide the correct token for the upstream server
		assert.Equal(t, "Bearer mock-token", r.Header.Get("Authorization"))
		// response
		if _, err := io.WriteString(w, "Upstream API Server Response!"); err != nil {
			t.Fatalf("Failed to write API server response: %v", err)
		}
	}))

	// load certs for mock API server
	serverCert, _ := tls.LoadX509KeyPair("../../test/data/api_server.crt", "../../test/data/api_server.key")

	apiServerTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	apiServer.TLS = apiServerTLSConfig

	// start API server
	apiServer.StartTLS()
	defer apiServer.Close()

	mockValidator := &mockValidator{
		shouldFail:       false,
		apiServerAddress: strings.TrimPrefix(apiServer.URL, "https://"),
	}

	// k8s proxy configuration
	cfg := Config{
		CA:                "../../test/data/api_server.crt",
		TLSCert:           "../../test/data/proxy_server.crt",
		TLSKey:            "../../test/data/proxy_server.key",
		K8sAPIServerURL:   apiServer.URL,
		K8sAPIServerToken: "mock-token",
		listenPort:        45678,
		ConnectValidator:  mockValidator,
	}

	// create and start the proxy
	proxy, err := NewProxy(cfg)
	require.NoError(t, err)

	ready := make(chan struct{})
	go func() {
		proxy.Start(ready)
	}()
	<-ready

	// downstream proxy and client certs
	caCert, _ := os.ReadFile("../../test/data/proxy_server.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
	}

	// manually create a TCP connection to be able to reuse for
	// HTTPS CONNECT (downstream proxy) then HTTPS requests (client)
	conn, err := net.Dial("tcp", "127.0.0.1:45678")
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// perform Proxy TLS handshake
	proxyTLSConn := tls.Client(conn, tlsConfig)
	if err := proxyTLSConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed(proxy): %v", err)
	}

	// setup CONNECT request with identity header (mock proxy's CONNECT request)
	connectReq, err := http.NewRequest(http.MethodConnect, apiServer.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	connectReq.Header.Set("Proxy-Authorization", "token")
	connectReq.Header.Set("X-Token-Signature", "signature")

	// send request
	if err := connectReq.Write(proxyTLSConn); err != nil {
		t.Fatalf("Failed to write CONNECT request: %v", err)
	}

	// read response
	connectResp, err := http.ReadResponse(bufio.NewReader(proxyTLSConn), connectReq)
	if err != nil {
		t.Fatalf("Failed to read CONNECT response: %v", err)
	}
	defer connectResp.Body.Close()

	// check 200 response
	assert.Equal(t, http.StatusOK, connectResp.StatusCode)

	// perform Client TLS handshake
	tlsConn := tls.Client(proxyTLSConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed(client): %v", err)
	}

	// create HTTP client that reuses the existing TLS connection (mock client)
	client := &http.Client{
		Transport: &http.Transport{
			DialTLS: func(_network, _addr string) (net.Conn, error) {
				return tlsConn, nil // use existing TLS connection
			},
		},
	}

	// setup HTTPS GET request
	getReq, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:45678", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// send request
	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer getResp.Body.Close()

	// check 200 response
	assert.Equal(t, http.StatusOK, getResp.StatusCode)

	// read response body
	body, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// check response
	assert.Equal(t, "Upstream API Server Response!", string(body))
}
