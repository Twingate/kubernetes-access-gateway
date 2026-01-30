// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httphandler

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"k8sgateway/internal/config"
	"k8sgateway/internal/connect"
	"k8sgateway/internal/token"
	"k8sgateway/test/data"
)

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

func TestProxy_ForwardRequest(t *testing.T) {
	t.Parallel()
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
	serverCert, err := tls.X509KeyPair(data.ServerCert, data.ServerKey)
	require.NoError(t, err)

	apiServerTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}
	apiServer.TLS = apiServerTLSConfig

	// start API server
	apiServer.StartTLS()
	defer apiServer.Close()

	apiServerAddress := strings.TrimPrefix(apiServer.URL, "https://")
	mockValidator := &mockValidator{
		shouldFail:       false,
		apiServerAddress: apiServerAddress,
	}

	// create TLS configuration for downstream
	cert, _ := tls.LoadX509KeyPair("../../test/data/proxy/tls.crt", "../../test/data/proxy/tls.key")
	downstreamTLSConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := listener.Addr().String()

	proxyListener := connect.NewListener(listener, downstreamTLSConfig, mockValidator, connect.CreateProxyConnMetrics(prometheus.NewRegistry()), zap.NewNop())

	// Check that listeners are created properly
	assert.Equal(t, addr, proxyListener.HTTPListener.Addr().String())
	assert.Equal(t, addr, proxyListener.SSHListener.Addr().String())

	go func() {
		_ = proxyListener.Serve()
	}()

	// k8s proxy configuration
	cfg := Config{
		ProtocolListener: proxyListener.HTTPListener,
		registry:         prometheus.NewRegistry(),
		upstream: &config.KubernetesUpstream{
			Address:     apiServerAddress,
			CAFile:      "../../test/data/api_server/tls.crt",
			BearerToken: "mock-token",
		},
		logger: zap.NewNop(),
	}

	// create and start the proxy
	httpProxy, err := NewProxy(cfg)
	require.NoError(t, err)

	go func() {
		_ = httpProxy.Start()
	}()

	// downstream proxy and client certs
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(data.ProxyCert)

	tlsConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS13,
	}

	// manually create a TCP connection to be able to reuse for
	// HTTPS CONNECT (downstream proxy) then HTTPS requests (client)
	conn, err := net.Dial("tcp", addr)
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
	getReq, err := http.NewRequest(http.MethodGet, "https://"+addr, nil)
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
	t.Parallel()
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
			t.Parallel()
			result := shouldSkipWebSocketRequest(tt.newRequestFn())
			assert.Equal(t, tt.expected, result)
		})
	}
}
