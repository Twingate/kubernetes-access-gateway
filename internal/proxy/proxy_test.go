// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gatewayconfig "k8sgateway/internal/config"
	"k8sgateway/internal/log"
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
	t.Parallel()
	registry := prometheus.NewRegistry()
	logger, err := log.NewLogger(log.DefaultName, false)
	require.NoError(t, err)

	p, err := NewProxy(&fullConfig, registry, logger)

	require.NoError(t, err)
	assert.NotNil(t, p)
	assert.Equal(t, &fullConfig, p.config)
	assert.Equal(t, registry, p.registry)
	assert.Equal(t, logger, p.logger)

	assert.NotNil(t, p.tokenParser)
	assert.NotNil(t, p.certReloader)
	assert.NotNil(t, p.tlsConfig)
	assert.NotNil(t, p.httpConfig)
	assert.NotNil(t, p.sshConfig)
}

func TestNewProxy_KubernetesOnly(t *testing.T) {
	t.Parallel()
	config := fullConfig
	config.SSH = nil

	registry := prometheus.NewRegistry()
	logger, err := log.NewLogger(log.DefaultName, false)
	require.NoError(t, err)

	p, err := NewProxy(&config, registry, logger)

	require.NoError(t, err)
	assert.NotNil(t, p)
	assert.NotNil(t, p.httpConfig)
	assert.Nil(t, p.sshConfig)
}

func TestNewProxy_SSHOnly(t *testing.T) {
	t.Parallel()
	config := fullConfig
	config.Kubernetes = nil

	registry := prometheus.NewRegistry()
	logger, err := log.NewLogger(log.DefaultName, false)
	require.NoError(t, err)

	p, err := NewProxy(&config, registry, logger)

	require.NoError(t, err)
	assert.NotNil(t, p)
	assert.NotNil(t, p.sshConfig)
	assert.Nil(t, p.httpConfig)
}
