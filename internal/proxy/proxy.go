// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"crypto/tls"
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
	"k8sgateway/internal/token"
)

type Proxy struct {
	config   *gatewayconfig.Config
	registry *prometheus.Registry
	logger   *zap.Logger

	tokenParser  *token.Parser
	tlsConfig    *tls.Config
	certReloader *connect.CertReloader
	httpConfig   *httphandler.Config
	sshConfig    *sshhandler.Config
}

func NewProxy(config *gatewayconfig.Config, registry *prometheus.Registry, logger *zap.Logger) (*Proxy, error) {
	tokenParser, err := token.NewParser(token.ParserConfig{
		Network: config.Twingate.Network,
		Host:    config.Twingate.Host,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create token parser %w", err)
	}

	certReloader := connect.NewCertReloader(config.TLS.CertificateFile, config.TLS.PrivateKeyFile, logger)

	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		MaxVersion:     tls.VersionTLS13,
		GetCertificate: certReloader.GetCertificate,
	}

	var httpConfig *httphandler.Config
	if config.Kubernetes != nil {
		httpConfig, err = httphandler.NewConfig(&config.AuditLog, config.Kubernetes, registry, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create Kubernetes config %w", err)
		}
	}

	var sshConfig *sshhandler.Config
	if config.SSH != nil {
		sshConfig, err = sshhandler.NewConfig(&config.AuditLog, config.SSH, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create SSH config %w", err)
		}
	}

	return &Proxy{
		config:   config,
		registry: registry,
		logger:   logger,

		tokenParser:  tokenParser,
		tlsConfig:    tlsConfig,
		certReloader: certReloader,
		httpConfig:   httpConfig,
		sshConfig:    sshConfig,
	}, nil
}

func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.config.Port))
	if err != nil {
		return err
	}

	g, gCtx := errgroup.WithContext(context.Background())

	p.certReloader.Run(gCtx)

	connectValidator := &connect.MessageValidator{
		TokenParser: p.tokenParser,
	}

	proxyListener := connect.NewListener(listener, p.tlsConfig, connectValidator, connect.CreateProxyConnMetrics(p.registry), p.logger)

	g.Go(func() error {
		p.logger.Info("Starting proxy listener", zap.Int("port", p.config.Port))

		err := proxyListener.Serve()
		if err != nil {
			p.logger.Error("Proxy listener stopped with error", zap.Error(err))
		}

		return err
	})

	if p.sshConfig != nil {
		p.sshConfig.ProtocolListener = proxyListener.GetSSHListener()

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
		p.httpConfig.ProtocolListener = proxyListener.GetHTTPListener()

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

	err = proxyListener.Stop()
	if err != nil {
		p.logger.Error("Failed to stop proxy listener", zap.Error(err))
	}

	return err
}
