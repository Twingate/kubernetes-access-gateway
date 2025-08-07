// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"k8sgateway/internal/connect"
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

func TestProxyConn_setConnectInfo(t *testing.T) {
	conn := &mockConn{}
	claims := &token.GATClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(50 * time.Millisecond)),
		},
	}
	connID := "conn-id-1"

	proxyConn := &ProxyConn{Conn: conn, tracker: newProxyConnMetricsTracker(connCategoryUnknown, createProxyConnMetrics(prometheus.NewRegistry()))}

	func() {
		// `setConnectInfo` should only be called after acquiring the lock. This is needed
		// because the timer is started in a separate goroutine.
		proxyConn.mu.Lock()
		defer proxyConn.mu.Unlock()

		proxyConn.setConnectInfo(connect.Info{
			Claims: claims,
			ConnID: connID,
		})
	}()

	assert.Equal(t, connID, proxyConn.id)
	assert.Equal(t, claims, proxyConn.claims)

	// Wait for timer to happen, the connection should be closed
	time.Sleep(100 * time.Millisecond)
	assert.True(t, conn.IsClosed())

	assert.Equal(t, connID, proxyConn.id)
	assert.Equal(t, claims, proxyConn.claims)

	// Wait for timer to happen, the connection should be closed
	time.Sleep(100 * time.Millisecond)
	assert.True(t, conn.IsClosed())
}

func TestProxyConn_Close(t *testing.T) {
	conn := &mockConn{}
	timer := time.NewTimer(0 * time.Millisecond)
	metrics := createProxyConnMetrics(prometheus.NewRegistry())
	proxyConn := &ProxyConn{
		Conn:    conn,
		timer:   timer,
		tracker: newProxyConnMetricsTracker(connCategoryUnknown, metrics),
	}

	_ = proxyConn.Close()

	assert.True(t, conn.IsClosed())

	// Verify that the timer was stopped
	select {
	case <-timer.C:
		assert.Fail(t, "Timer should have been stopped")
	default:
	}

	// Ensure metrics are only measured once
	_ = proxyConn.Close()

	count := promtestutil.ToFloat64(metrics.connTotal)
	assert.Equal(t, 1, int(count))
}

var errValidation = &connect.HTTPError{
	Code:    http.StatusProxyAuthRequired,
	Message: "failed to validate token",
}

type mockValidator struct {
	shouldFail       bool
	ProxyAuth        string
	TokenSig         string
	ConnID           string
	apiServerAddress string
}

func (m *mockValidator) ParseConnect(req *http.Request, _ []byte) (connectInfo connect.Info, err error) {
	if m.shouldFail {
		return connect.Info{
			Claims: nil,
			ConnID: "",
		}, errValidation
	}

	claims := &token.GATClaims{
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
	m.ConnID = req.Header.Get(connect.ConnIDHeaderKey)

	return connect.Info{Claims: claims, ConnID: m.ConnID}, nil
}

func startMockListener(t *testing.T) (net.Listener, string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := listener.Addr().String()

	return listener, addr
}

func TestProxyConn_Read_BadRequest(t *testing.T) {
	listener, addr := startMockListener(t)
	defer listener.Close()

	// make proxy TLS
	serverCert, _ := tls.LoadX509KeyPair("../../test/data/proxy/tls.crt", "../../test/data/proxy/tls.key")

	proxyTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}

	// mock CONNECT validator
	mockValidator := &mockValidator{
		shouldFail: false,
	}

	listener = &proxyListener{
		Listener:         listener,
		TLSConfig:        proxyTLSConfig,
		ConnectValidator: mockValidator,
		logger:           zap.NewNop(),
		metrics:          createProxyConnMetrics(prometheus.NewRegistry()),
	}

	// make client TLS
	caCert, _ := os.ReadFile("../../test/data/proxy/tls.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientTLSConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS13,
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
		_, err = fmt.Fprint(proxyTLSConn, "invalid-request\r\n\r\n")
		assert.NoError(t, err)

		resp, err := bufio.NewReader(proxyTLSConn).ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 400 Bad Request\r\n", resp)

		done <- struct{}{}
	}()

	conn, err := listener.Accept()
	require.NoError(t, err)

	b := make([]byte, 0)
	_, err = conn.Read(b)
	assert.ErrorContains(t, err, "malformed HTTP request \"invalid-request\"")

	<-done
}

func TestProxyConn_Read_HealthCheck(t *testing.T) {
	listener, addr := startMockListener(t)
	defer listener.Close()

	// make proxy TLS
	serverCert, _ := tls.LoadX509KeyPair("../../test/data/proxy/tls.crt", "../../test/data/proxy/tls.key")

	proxyTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}

	listener = &proxyListener{
		Listener:  listener,
		TLSConfig: proxyTLSConfig,
		metrics:   createProxyConnMetrics(prometheus.NewRegistry()),
	}

	// make client TLS
	caCert, _ := os.ReadFile("../../test/data/proxy/tls.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientTLSConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS13,
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
		_, err = fmt.Fprint(proxyTLSConn, "GET /healthz HTTP/1.1\r\n\r\n")
		assert.NoError(t, err)

		buf := bufio.NewReader(proxyTLSConn)
		resp, err := buf.ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 200 OK\r\n", resp)
		resp, err = buf.ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "Content-Length: 0\r\n", resp)
		resp, err = buf.ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "Connection: close\r\n", resp)

		done <- struct{}{}
	}()

	conn, err := listener.Accept()
	require.NoError(t, err)

	b := make([]byte, 0)
	_, err = conn.Read(b)
	require.ErrorIs(t, io.EOF, err)

	<-done
}

func TestProxyConn_Read_ValidConnectRequest(t *testing.T) {
	listener, addr := startMockListener(t)
	defer listener.Close()

	proxyCert, _ := tls.LoadX509KeyPair("../../test/data/proxy/tls.crt", "../../test/data/proxy/tls.key")

	proxyTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{proxyCert},
		MinVersion:   tls.VersionTLS13,
	}

	// mock CONNECT validator
	mockValidator := &mockValidator{
		shouldFail: false,
	}

	listener = &proxyListener{
		Listener:         listener,
		TLSConfig:        proxyTLSConfig,
		ConnectValidator: mockValidator,
		logger:           zap.NewNop(),
		metrics:          createProxyConnMetrics(prometheus.NewRegistry()),
	}

	// make client TLS
	caCert, _ := os.ReadFile("../../test/data/proxy/tls.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientTLSConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS13,
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
		_, err = fmt.Fprintf(proxyTLSConn, "CONNECT example.com:443 HTTP/1.1\r\n%s: gat_token\r\n%s: auth_sig\r\n%s: conn-id-1\r\n\r\n",
			connect.AuthHeaderKey, connect.AuthSignatureHeaderKey, connect.ConnIDHeaderKey)
		assert.NoError(t, err)

		// expect 200 Connection Established back
		resp, err := bufio.NewReader(proxyTLSConn).ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 200 OK\r\n", resp)

		// establish second TLS (as downstream client)
		clientTLSConn := tls.Client(proxyTLSConn, clientTLSConfig)
		if err := clientTLSConn.Handshake(); err != nil {
			done <- struct{}{}

			return
		}

		done <- struct{}{}
	}()

	conn, err := listener.Accept()
	require.NoError(t, err)

	b := make([]byte, 0)
	_, err = conn.Read(b)
	require.NoError(t, err)

	<-done

	assert.IsType(t, &ProxyConn{}, conn)
	proxyConn := conn.(*ProxyConn)
	assert.Equal(t, "user@acme.com", proxyConn.claims.User.Username)
	assert.ElementsMatch(t, []string{"Everyone", "Engineering"}, proxyConn.claims.User.Groups)
	assert.Equal(t, "gat_token", mockValidator.ProxyAuth)
	assert.Equal(t, "auth_sig", mockValidator.TokenSig)
	assert.Equal(t, "conn-id-1", mockValidator.ConnID)
}

func TestProxyConn_Read_FailedValidation(t *testing.T) {
	listener, addr := startMockListener(t)
	defer listener.Close()

	// make proxy TLS
	serverCert, _ := tls.LoadX509KeyPair("../../test/data/proxy/tls.crt", "../../test/data/proxy/tls.key")

	proxyTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}

	// mock CONNECT validator
	mockValidator := &mockValidator{
		shouldFail: true,
	}

	listener = &proxyListener{
		Listener:         listener,
		TLSConfig:        proxyTLSConfig,
		ConnectValidator: mockValidator,
		logger:           zap.NewNop(),
		metrics:          createProxyConnMetrics(prometheus.NewRegistry()),
	}

	// make client TLS
	caCert, _ := os.ReadFile("../../test/data/proxy/tls.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientTLSConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS13,
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

		_, err = fmt.Fprintf(proxyTLSConn, "CONNECT example.com:443 HTTP/1.1\r\n%s: bad_token\r\n%s: auth_sig\r\n%s: conn-id-1\r\n\r\n",
			connect.AuthHeaderKey, connect.AuthSignatureHeaderKey, connect.ConnIDHeaderKey)
		assert.NoError(t, err)

		resp, err := bufio.NewReader(proxyTLSConn).ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 407 Proxy Authentication Required\r\n", resp)

		done <- struct{}{}
	}()

	conn, err := listener.Accept()
	require.NoError(t, err)

	b := make([]byte, 0)
	_, err = conn.Read(b)
	assert.ErrorIs(t, err, errValidation)

	<-done
}

func TestProxy_ForwardRequest(t *testing.T) {
	// create mock API server (upstream)
	apiServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// proxy should provide the correct 'Impersonate-User' header
		assert.Equal(t, "user@acme.com", r.Header.Get("Impersonate-User"))
		// proxy should provide the correct 'Impersonate-Groups' header
		assert.Equal(t, []string{"Everyone", "Engineering"}, r.Header.Values("Impersonate-Group"))
		// proxy should provide the correct token for the upstream server
		assert.Equal(t, "Bearer mock-token", r.Header.Get("Authorization"))
		// response
		_, err := io.WriteString(w, "Upstream API Server Response!")
		assert.NoError(t, err)
	}))

	// load certs for mock API server
	serverCert, _ := tls.LoadX509KeyPair("../../test/data/api_server/tls.crt", "../../test/data/api_server/tls.key")

	apiServerTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
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
		TLSCert:           "../../test/data/proxy/tls.crt",
		TLSKey:            "../../test/data/proxy/tls.key",
		K8sAPIServerCA:    "../../test/data/api_server/tls.crt",
		K8sAPIServerToken: "mock-token",
		ConnectValidator:  mockValidator,
		Port:              45678,
		Registry:          prometheus.NewRegistry(),
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
	caCert, _ := os.ReadFile("../../test/data/proxy/tls.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS13,
	}

	// manually create a TCP connection to be able to reuse for
	// HTTPS CONNECT (downstream proxy) then HTTPS requests (client)
	conn, err := net.Dial("tcp", "127.0.0.1:45678")
	require.NoError(t, err, "Failed to connect to proxy")

	defer conn.Close()

	// perform Proxy TLS handshake
	proxyTLSConn := tls.Client(conn, tlsConfig)
	require.NoError(t, proxyTLSConn.Handshake(), "TLS handshake failed(proxy)")

	// setup CONNECT request with identity header (mock proxy's CONNECT request)
	connectReq, err := http.NewRequest(http.MethodConnect, apiServer.URL, nil)
	require.NoError(t, err, "Failed to create request")

	connectReq.Header.Set("Proxy-Authorization", "token")
	connectReq.Header.Set("X-Token-Signature", "signature")
	connectReq.Header.Set("X-Connection-Id", "conn-id")

	// send request
	require.NoError(t, connectReq.Write(proxyTLSConn), "Failed to write CONNECT request")

	// read response
	connectResp, err := http.ReadResponse(bufio.NewReader(proxyTLSConn), connectReq)
	require.NoError(t, err, "Failed to read CONNECT response")

	defer connectResp.Body.Close()

	// check 200 response
	assert.Equal(t, http.StatusOK, connectResp.StatusCode)

	// perform Client TLS handshake
	tlsConn := tls.Client(proxyTLSConn, tlsConfig)
	require.NoError(t, tlsConn.Handshake(), "TLS handshake failed(client)")

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
	require.NoError(t, err, "Failed to create request")

	// send request
	getResp, err := client.Do(getReq)
	require.NoError(t, err, "Failed to send request")

	defer getResp.Body.Close()

	// check 200 response
	assert.Equal(t, http.StatusOK, getResp.StatusCode)

	// read response body
	body, err := io.ReadAll(getResp.Body)
	require.NoError(t, err, "Failed to read response body")

	// check response
	assert.Equal(t, "Upstream API Server Response!", string(body))
}

func TestShouldSkipWebSocketRequest(t *testing.T) {
	tests := []struct {
		name         string
		newRequestFn func() *http.Request
		expected     bool
	}{
		{
			name: "WebSocket request with tunneling protocol",
			newRequestFn: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Connection", "upgrade")
				r.Header.Set("Sec-WebSocket-Protocol", "SPDY/3.1+portforward.k8s.io")

				return r
			},
			expected: true,
		},
		{
			name: "WebSocket request with `kubectl cp` command",
			newRequestFn: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Kubectl-Command", "kubectl cp")

				return r
			},
			expected: true,
		},
		{
			name: "WebSocket request with tar command",
			newRequestFn: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods/pod-1/exec?command=tar", nil)
			},
			expected: true,
		},
		{
			name: "WebSocket request with other command",
			newRequestFn: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods/pod-1/exec?command=ls", nil)
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldSkipWebSocketRequest(tt.newRequestFn())
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsHealthCheckRequest(t *testing.T) {
	testCases := []struct {
		name           string
		request        *http.Request
		expectedResult bool
	}{
		{
			name:           "Healthcheck request",
			request:        httptest.NewRequest(http.MethodGet, healthCheckPath, nil),
			expectedResult: true,
		},
		{
			name:           "POST request to healthcheck path",
			request:        httptest.NewRequest(http.MethodPost, healthCheckPath, nil),
			expectedResult: false,
		},
		{
			name:           "Proxy request",
			request:        httptest.NewRequest(http.MethodConnect, "", nil),
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedResult, isHealthCheckRequest(tc.request))
		})
	}
}
