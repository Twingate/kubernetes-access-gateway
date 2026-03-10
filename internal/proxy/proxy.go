// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"fmt"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	gatewayconfig "k8sgateway/internal/config"
	"k8sgateway/internal/connect"
	"k8sgateway/internal/httphandler"
	"k8sgateway/internal/metrics"
	"k8sgateway/internal/sessionrecorder"
	"k8sgateway/internal/sshhandler"
)

type Proxy struct {
	config   *gatewayconfig.Config
	registry *prometheus.Registry
	logger   *zap.Logger

	httpConfig *httphandler.Config
	sshConfig  *sshhandler.Config
}

func NewProxy(config *gatewayconfig.Config, registry *prometheus.Registry, logger *zap.Logger) (*Proxy, error) {
	var httpConfig *httphandler.Config

	if config.Kubernetes != nil {
		var err error

		httpConfig, err = httphandler.NewConfig(&config.AuditLog, config.Kubernetes, registry, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create Kubernetes config %w", err)
		}
	}

	var sshConfig *sshhandler.Config

	if config.SSH != nil {
		var err error

		sshConfig, err = sshhandler.NewConfig(&config.AuditLog, config.SSH, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create SSH config %w", err)
		}
	}

	return &Proxy{
		config:   config,
		registry: registry,
		logger:   logger,

		httpConfig: httpConfig,
		sshConfig:  sshConfig,
	}, nil
}

func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.config.Port))
	if err != nil {
		return err
	}

	channels := make(map[connect.TransportProtocol]chan<- connect.Conn)

	var sshListener *connect.ProtocolListener

	if p.sshConfig != nil {
		sshChannel := make(chan connect.Conn)
		channels[connect.TransportSSH] = sshChannel
		sshListener = connect.NewProtocolListener(sshChannel, listener.Addr())
	}

	var httpListener *connect.ProtocolListener

	if p.httpConfig != nil {
		httpChannel := make(chan connect.Conn)
		channels[connect.TransportTLS] = httpChannel
		httpListener = connect.NewProtocolListener(httpChannel, listener.Addr())
	}

	connectListener, err := connect.NewListener(
		p.config.Twingate,
		p.config.TLS,
		channels,
		p.registry,
		p.logger,
	)
	if err != nil {
		return fmt.Errorf("failed to create connect listener: %w", err)
	}

	g, gCtx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		p.logger.Info("Starting connect proxy", zap.Int("port", p.config.Port))

		err := connectListener.Serve(gCtx, listener)
		if err != nil {
			p.logger.Error("Connect proxy stopped with error", zap.Error(err))
		}

		return err
	})

	if p.sshConfig != nil {
		p.sshConfig.ProtocolListener = sshListener

		sshProxy := sshhandler.NewProxy(*p.sshConfig)

		g.Go(func() error {
			p.logger.Info("Starting SSH proxy")

			err := sshProxy.Start(gCtx)
			if err != nil {
				p.logger.Error("SSH proxy stopped with error", zap.Error(err))
			}

			return err
		})
	}

	if p.httpConfig != nil {
		p.httpConfig.ProtocolListener = httpListener

		httpProxy, err := httphandler.NewProxy(*p.httpConfig)
		if err != nil {
			return err
		}

		g.Go(func() error {
			p.logger.Info("Starting HTTP proxy")

			err := httpProxy.Start()
			if err != nil {
				p.logger.Error("HTTP proxy stopped with error", zap.Error(err))
			}

			return err
		})
	}

	g.Go(func() error {
		p.logger.Info("Starting metrics server", zap.Int("port", p.config.MetricsPort))

		sessionrecorder.RegisterRecordedSessionMetrics(metrics.Namespace, p.registry)

		err := metrics.Start(metrics.Config{
			Port:     p.config.MetricsPort,
			Registry: p.registry,
		})
		if err != nil {
			p.logger.Error("Metrics server stopped with error", zap.Error(err))
		}

		return err
	})

	err = g.Wait()
	if err != nil {
		p.logger.Error("Proxy component error", zap.Error(err))
	}

	if closeErr := listener.Close(); closeErr != nil {
		p.logger.Error("Failed to close listener", zap.Error(closeErr))
	}

	return err
}
