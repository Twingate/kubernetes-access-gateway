// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	gatewayconfig "k8sgateway/internal/config"
	"k8sgateway/internal/connect"
	"k8sgateway/internal/httphandler"
	"k8sgateway/internal/log"
	"k8sgateway/internal/metrics"
	"k8sgateway/internal/sshhandler"
)

var fullConfig = gatewayconfig.Config{
	Twingate: gatewayconfig.TwingateConfig{
		Network: "acme",
		Host:    "test",
	},
	Port:        0,
	MetricsPort: 0,
	TLS: gatewayconfig.TLSConfig{
		CertificateFile: "../../test/data/proxy/tls.crt",
		PrivateKeyFile:  "../../test/data/proxy/tls.key",
	},
	Kubernetes: &gatewayconfig.KubernetesConfig{
		Upstreams: []gatewayconfig.KubernetesUpstream{
			{
				Name:        "k8s-cluster",
				Address:     "127.0.0.1:6443",
				BearerToken: "token",
				CAFile:      "../../test/data/api_server/tls.crt",
			},
		},
	},
	SSH: &gatewayconfig.SSHConfig{
		Gateway: gatewayconfig.SSHGatewayConfig{
			Username:        "gateway",
			Key:             gatewayconfig.SSHKeyConfig{},
			HostCertificate: gatewayconfig.SSHCertificateConfig{},
			UserCertificate: gatewayconfig.SSHCertificateConfig{},
		},
		CA: gatewayconfig.SSHCAConfig{},
		Upstreams: []gatewayconfig.SSHUpstream{
			{
				Name:    "ssh-server",
				Address: "127.0.0.1:22",
			},
		},
	},
}

func TestNewProxy_Success(t *testing.T) {
	registry := prometheus.NewRegistry()
	logger, err := log.NewLogger(log.DefaultName, false)
	require.NoError(t, err)

	p, err := NewProxy(&fullConfig, registry, logger)

	require.NoError(t, err)
	assert.NotNil(t, p)
	assert.Equal(t, &fullConfig, p.config)
	assert.Equal(t, registry, p.registry)
	assert.Equal(t, logger, p.logger)

	assert.NotNil(t, p.httpProxy)
	assert.NotNil(t, p.sshProxy)
	assert.NotNil(t, p.metricsServer)
}

func TestNewProxy_KubernetesOnly(t *testing.T) {
	config := fullConfig
	config.SSH = nil

	registry := prometheus.NewRegistry()
	logger, err := log.NewLogger(log.DefaultName, false)
	require.NoError(t, err)

	p, err := NewProxy(&config, registry, logger)

	require.NoError(t, err)
	assert.NotNil(t, p)
	assert.NotNil(t, p.httpProxy)
	assert.Nil(t, p.sshProxy)
}

func TestNewProxy_SSHOnly(t *testing.T) {
	config := fullConfig
	config.Kubernetes = nil

	registry := prometheus.NewRegistry()
	logger, err := log.NewLogger(log.DefaultName, false)
	require.NoError(t, err)

	p, err := NewProxy(&config, registry, logger)

	require.NoError(t, err)
	assert.NotNil(t, p)
	assert.NotNil(t, p.sshProxy)
	assert.Nil(t, p.httpProxy)
}

func createTestProxy(t *testing.T) (*Proxy, int) {
	t.Helper()

	// Create a real TCP listener on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// Get a free port for the metrics server
	metricsListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	metricsPort := metricsListener.Addr().(*net.TCPAddr).Port
	// Close so the metrics server can bind to this port
	require.NoError(t, metricsListener.Close())

	registry := prometheus.NewRegistry()
	metricsServer := metrics.NewServer(metrics.Config{
		Port:     metricsPort,
		Registry: registry,
	})

	return &Proxy{
		logger:        zap.NewNop(),
		listener:      listener,
		metricsServer: metricsServer,
	}, metricsPort
}

func TestShutdown_ClosesAllComponents(t *testing.T) {
	p, metricsPort := createTestProxy(t)

	// Create and attach a real HTTP proxy
	registry := prometheus.NewRegistry()

	httpConfig, err := httphandler.NewConfig(
		&gatewayconfig.AuditLogConfig{},
		fullConfig.Kubernetes,
		registry,
		zap.NewNop(),
	)
	require.NoError(t, err)

	httpProxy, err := httphandler.NewProxy(*httpConfig)
	require.NoError(t, err)

	p.httpProxy = httpProxy

	// Start HTTP proxy on a protocol listener
	httpChannel := make(chan connect.Conn)
	httpListener := connect.NewProtocolListener(httpChannel, p.listener.Addr())

	httpDone := make(chan error, 1)

	go func() {
		httpDone <- p.httpProxy.Start(httpListener)
	}()

	// Create and attach a real SSH proxy
	sshConfig, err := sshhandler.NewConfig(
		&gatewayconfig.AuditLogConfig{},
		fullConfig.SSH,
		zap.NewNop(),
	)
	require.NoError(t, err)

	p.sshProxy = sshhandler.NewProxy(*sshConfig)

	// Start metrics server
	go func() {
		_ = p.metricsServer.Start()
	}()

	listenerAddr := p.listener.Addr().String()
	metricsAddr := fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort)

	p.shutdown()

	// Listener should be closed
	_, err = net.DialTimeout("tcp", listenerAddr, 100*time.Millisecond)
	assert.Error(t, err)

	// Metrics server should be closed
	client := &http.Client{Timeout: 100 * time.Millisecond}
	_, err = client.Get(metricsAddr) //nolint:noctx
	assert.Error(t, err)

	// HTTP proxy should have stopped with ErrServerClosed
	close(httpChannel)

	select {
	case httpErr := <-httpDone:
		assert.True(t, errors.Is(httpErr, http.ErrServerClosed))
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for HTTP proxy to stop")
	}
}

func TestShutdown_IsIdempotent(t *testing.T) {
	p, _ := createTestProxy(t)

	go func() {
		_ = p.metricsServer.Start()
	}()

	// Calling shutdown multiple times should not panic
	p.shutdown()
	p.shutdown()
}

func TestShutdown_NilComponents(t *testing.T) {
	registry := prometheus.NewRegistry()
	metricsServer := metrics.NewServer(metrics.Config{
		Port:     0,
		Registry: registry,
	})

	go func() {
		_ = metricsServer.Start()
	}()

	p := &Proxy{
		logger:        zap.NewNop(),
		listener:      nil,
		httpProxy:     nil,
		sshProxy:      nil,
		metricsServer: metricsServer,
	}

	// Should not panic with nil listener, httpProxy, and sshProxy
	p.shutdown()
}
