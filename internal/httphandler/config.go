// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httphandler

import (
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"k8s.io/client-go/rest"

	"k8sgateway/internal/config"
	"k8sgateway/internal/connect"
)

type Config struct {
	ProtocolListener *connect.ProtocolListener

	auditLog *config.AuditLogConfig
	registry *prometheus.Registry
	upstream *config.KubernetesUpstream
	logger   *zap.Logger
}

func NewConfig(auditLogConfig *config.AuditLogConfig, k8sConfig *config.KubernetesConfig, registry *prometheus.Registry, logger *zap.Logger) (*Config, error) {
	// Multiple upstreams support will be added soon!
	upstream, err := GetInClusterConfig(&k8sConfig.Upstreams[0])
	if err != nil {
		return nil, err
	}

	return &Config{
		auditLog: auditLogConfig,
		registry: registry,
		upstream: upstream,
		logger:   logger,
	}, nil
}

const inClusterKubernetesServiceAddress = "kubernetes.default.svc.cluster.local:443"

func GetInClusterConfig(upstream *config.KubernetesUpstream) (*config.KubernetesUpstream, error) {
	if !upstream.InCluster {
		return upstream, nil
	}

	inClusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return upstream, err
	}

	upstream.Address = inClusterKubernetesServiceAddress
	upstream.BearerToken = inClusterConfig.BearerToken
	upstream.BearerTokenFile = inClusterConfig.BearerTokenFile
	upstream.CAFile = inClusterConfig.CAFile

	return upstream, nil
}
