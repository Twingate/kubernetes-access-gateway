// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"k8sgateway/internal/token"
)

type mockProxyConn struct {
	net.Conn

	transportProtocol TransportProtocol
	Claims            *token.GATClaims

	isClosed atomic.Bool

	isHealthz bool
}

func (m *mockProxyConn) Close() error {
	_ = m.Conn.Close()
	m.isClosed.Store(true)

	return nil
}

func (m *mockProxyConn) IsClosed() bool {
	return m.isClosed.Load()
}

func (m *mockProxyConn) TransportProtocol() TransportProtocol {
	return m.transportProtocol
}

func (m *mockProxyConn) GATClaims() *token.GATClaims {
	return m.Claims
}

func (m *mockProxyConn) GetID() string {
	return "mock"
}

func (m *mockProxyConn) GetAddress() string {
	return "mock"
}

func (m *mockProxyConn) Authenticate() error {
	if m.isHealthz {
		// write health check response
		_, err := m.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		if err != nil {
			return err
		}

		return io.EOF
	}

	return nil
}

func (m *mockProxyConn) UpgradeToTLS() error {
	return nil
}

func createMockListener(t *testing.T) (net.Listener, string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := listener.Addr().String()

	return listener, addr
}

var listenerClaims = &token.GATClaims{
	RegisteredClaims: jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	},
	User: token.User{
		ID:       "user-1",
		Username: "user@acme.com",
		Groups:   []string{"Everyone", "Engineering"},
	},
	Resource: token.Resource{ID: "resource-1", Type: token.ResourceTypeKubernetes, Address: "https://api.acme.com"},
}

func TestProxyListener_Serve_HTTPS(t *testing.T) {
	listener, addr := createMockListener(t)

	proxyListener := NewListener(listener, nil, nil, CreateProxyConnMetrics(prometheus.NewRegistry()), zap.L())

	proxyListener.proxyConnFactory = func(conn net.Conn, _ *tls.Config, _ Validator, _ *zap.Logger) Conn {
		return &mockProxyConn{
			Conn:              conn,
			transportProtocol: TransportTLS,
			Claims:            listenerClaims,
		}
	}

	go func() {
		_ = proxyListener.Serve()
	}()

	// Open TCP connection to the mock listener
	go func() {
		_, err := net.Dial("tcp", addr)
		assert.NoError(t, err)
	}()

	// Listen for SSH connections, we should not receive any
	waitGroup := sync.WaitGroup{}

	waitGroup.Go(func() {
		conn, err := proxyListener.SSHListener.Accept()
		assert.Nil(t, conn)
		assert.ErrorIs(t, err, net.ErrClosed)
	})

	// Accept the HTTP connection
	conn, err := proxyListener.HTTPListener.Accept()
	require.NoError(t, err)
	require.False(t, conn.(*mockProxyConn).IsClosed())
	require.Equal(t, TransportTLS, conn.(*mockProxyConn).TransportProtocol())
	require.Equal(t, listenerClaims, conn.(*mockProxyConn).Claims)

	// Close the listener
	_ = proxyListener.Stop()

	// Wait for the SSH listener to close without accepting any connections
	waitGroup.Wait()

	// Check that HTTP listener is closed too
	conn, err = proxyListener.HTTPListener.Accept()
	assert.Nil(t, conn)
	assert.ErrorIs(t, err, net.ErrClosed)
}

func TestProxyListener_Serve_SSH(t *testing.T) {
	listener, addr := createMockListener(t)

	proxyListener := NewListener(listener, nil, nil, CreateProxyConnMetrics(prometheus.NewRegistry()), zap.L())

	proxyListener.proxyConnFactory = func(conn net.Conn, _ *tls.Config, _ Validator, _ *zap.Logger) Conn {
		return &mockProxyConn{
			Conn:              conn,
			transportProtocol: TransportSSH,
			Claims:            listenerClaims,
		}
	}

	go func() {
		_ = proxyListener.Serve()
	}()

	// Open TCP connection to the mock listener
	go func() {
		_, err := net.Dial("tcp", addr)
		assert.NoError(t, err)
	}()

	// Listen for HTTP connections, we should not receive any
	waitGroup := sync.WaitGroup{}

	waitGroup.Go(func() {
		conn, err := proxyListener.HTTPListener.Accept()
		assert.Nil(t, conn)
		assert.ErrorIs(t, err, net.ErrClosed)
	})

	// Accept the SSH connection
	conn, err := proxyListener.SSHListener.Accept()
	require.NoError(t, err)
	require.False(t, conn.(*mockProxyConn).IsClosed())
	require.Equal(t, TransportSSH, conn.(*mockProxyConn).TransportProtocol())
	require.Equal(t, listenerClaims, conn.(*mockProxyConn).Claims)

	// Close the listener
	_ = proxyListener.Stop()

	// Wait for the HTTP listener to close without accepting any connections
	waitGroup.Wait()

	// Check that SSH listener is closed too
	conn, err = proxyListener.SSHListener.Accept()
	assert.Nil(t, conn)
	assert.ErrorIs(t, err, net.ErrClosed)
}

func TestProxyListener_Serve_Healthz(t *testing.T) {
	listener, addr := createMockListener(t)

	proxyListener := NewListener(listener, nil, nil, CreateProxyConnMetrics(prometheus.NewRegistry()), zap.L())

	proxyListener.proxyConnFactory = func(conn net.Conn, _ *tls.Config, _ Validator, _ *zap.Logger) Conn {
		return &mockProxyConn{
			Conn:      conn,
			isHealthz: true,
		}
	}

	go func() {
		_ = proxyListener.Serve()
	}()

	// Open TCP connection to the mock listener
	done := make(chan struct{})

	go func() {
		conn, err := net.Dial("tcp", addr)
		assert.NoError(t, err)
		// Read the health check response
		buf := bufio.NewReader(conn)
		resp, err := buf.ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 200 OK\r\n", resp)
		// Continue reading, should be closed with EOF
		_, err = conn.Read(make([]byte, 1))
		assert.ErrorIs(t, err, io.EOF)

		done <- struct{}{}
	}()

	// To wait for listeners to close
	waitGroup := sync.WaitGroup{}
	waitGroup.Add(2)
	// We should not accept any HTTP connections
	go func() {
		conn, err := proxyListener.HTTPListener.Accept()
		assert.Nil(t, conn)
		assert.ErrorIs(t, err, net.ErrClosed)
		waitGroup.Done()
	}()

	// We should not accept any SSH connections
	go func() {
		conn, err := proxyListener.SSHListener.Accept()
		assert.Nil(t, conn)
		assert.ErrorIs(t, err, net.ErrClosed)
		waitGroup.Done()
	}()

	// Wait for health check connection to finish
	<-done

	// Close the listener
	_ = proxyListener.Stop()

	// Now wait for all listeners to close properly
	waitGroup.Wait()
}

func TestProtocolListener(t *testing.T) {
	listener, addr := createMockListener(t)

	proxyListener := NewListener(listener, nil, nil, CreateProxyConnMetrics(prometheus.NewRegistry()), zap.L())
	proxyListener.proxyConnFactory = func(conn net.Conn, _ *tls.Config, _ Validator, _ *zap.Logger) Conn {
		return &mockProxyConn{
			Conn: conn,
		}
	}

	// Check that listeners are created properly
	assert.Equal(t, addr, proxyListener.HTTPListener.Addr().String())
	assert.Equal(t, addr, proxyListener.SSHListener.Addr().String())

	go func() {
		_ = proxyListener.Serve()
	}()

	// Close HTTP listener, check that it is closed
	_ = proxyListener.HTTPListener.Close()
	conn, err := proxyListener.HTTPListener.Accept()
	assert.Nil(t, conn)
	require.ErrorIs(t, err, net.ErrClosed)

	// Close SSH listener, check that it is closed
	_ = proxyListener.SSHListener.Close()
	conn, err = proxyListener.SSHListener.Accept()
	assert.Nil(t, conn)
	require.ErrorIs(t, err, net.ErrClosed)

	// Close a listener again, should not panic
	_ = proxyListener.HTTPListener.Close()

	// Close the proxy listener now
	_ = proxyListener.Stop()

	// Check the inner listener is closed
	conn, err = listener.Accept()
	assert.Nil(t, conn)
	require.ErrorIs(t, err, net.ErrClosed)
}
