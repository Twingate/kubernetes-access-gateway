// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httphandler

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"k8sgateway/internal/config"
)

func TestNewConfig(t *testing.T) {
	auditLogConfig := &config.AuditLogConfig{
		FlushInterval:      60,
		FlushSizeThreshold: 1000,
	}
	registry := prometheus.NewRegistry()

	t.Run("Success with non in-cluster upstream", func(t *testing.T) {
		k8sConfig := &config.KubernetesConfig{
			Upstreams: []config.KubernetesUpstream{
				{
					Name:            "test-upstream",
					InCluster:       false,
					Address:         "k8s.example.com:6443",
					BearerToken:     "test-token",
					BearerTokenFile: "",
					CAFile:          "/path/to/ca.crt",
				},
			},
		}

		cfg, err := NewConfig(auditLogConfig, k8sConfig, registry, zap.NewNop())

		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, auditLogConfig, cfg.auditLog)
		assert.Equal(t, registry, cfg.registry)
		assert.Equal(t, &k8sConfig.Upstreams[0], cfg.upstream)
		assert.Nil(t, cfg.ProtocolListener)
	})

	t.Run("Error when GetInClusterConfig fails", func(t *testing.T) {
		// Clear environment to force in-cluster config to fail
		t.Setenv("KUBERNETES_SERVICE_HOST", "")

		k8sConfig := &config.KubernetesConfig{
			Upstreams: []config.KubernetesUpstream{
				{
					Name:      "in-cluster-fail",
					InCluster: true,
				},
			},
		}

		cfg, err := NewConfig(auditLogConfig, k8sConfig, registry, zap.NewNop())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to load in-cluster configuration")
		assert.Nil(t, cfg)
	})
}

func TestGetInClusterConfig(t *testing.T) {
	tests := []struct {
		name          string
		upstream      *config.KubernetesUpstream
		setupEnv      func(t *testing.T)
		expectError   bool
		errorContains string
		validate      func(t *testing.T, result *config.KubernetesUpstream)
	}{
		{
			name: "Non in-cluster upstream returns unchanged",
			upstream: &config.KubernetesUpstream{
				Name:        "external",
				InCluster:   false,
				Address:     "k8s.internal:6443",
				BearerToken: "external-token",
				CAFile:      "/path/to/ca.crt",
			},
			setupEnv:    func(_ *testing.T) {},
			expectError: false,
			validate: func(t *testing.T, result *config.KubernetesUpstream) {
				t.Helper()

				assert.Equal(t, "external", result.Name)
				assert.False(t, result.InCluster)
				assert.Equal(t, "k8s.internal:6443", result.Address)
				assert.Equal(t, "external-token", result.BearerToken)
				assert.Equal(t, "/path/to/ca.crt", result.CAFile)
			},
		},
		{
			name: "In-cluster upstream preserves original upstream on error",
			upstream: &config.KubernetesUpstream{
				Name:      "in-cluster-preserve",
				InCluster: true,
				Address:   "original-address",
			},
			setupEnv: func(t *testing.T) {
				t.Helper()

				t.Setenv("KUBERNETES_SERVICE_HOST", "0.0.0.0")
			},
			expectError:   true,
			errorContains: "unable to load in-cluster configuration",
			validate: func(t *testing.T, result *config.KubernetesUpstream) {
				t.Helper()

				// Even on error, the function returns the original upstream
				assert.Equal(t, "in-cluster-preserve", result.Name)
				assert.Equal(t, "original-address", result.Address)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv(t)

			result, err := GetInClusterConfig(tt.upstream)

			if tt.expectError {
				require.Error(t, err)

				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}

			require.NotNil(t, result)

			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}
