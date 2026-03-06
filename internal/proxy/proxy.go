// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

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

const shutdownTimeout = 30 * time.Second

type Proxy struct {
	config   *gatewayconfig.Config
	registry *prometheus.Registry
	logger   *zap.Logger

	httpProxy     *httphandler.Proxy
	sshProxy      *sshhandler.SSHProxy
	metricsServer *metrics.Server

	listener     net.Listener
	shutdownOnce sync.Once
}

func NewProxy(config *gatewayconfig.Config, registry *prometheus.Registry, logger *zap.Logger) (*Proxy, error) {
	var httpProxy *httphandler.Proxy

	if config.Kubernetes != nil {
		httpConfig, err := httphandler.NewConfig(&config.AuditLog, config.Kubernetes, registry, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create Kubernetes config %w", err)
		}

		httpProxy, err = httphandler.NewProxy(*httpConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP proxy: %w", err)
		}
	}

	var sshProxy *sshhandler.SSHProxy

	if config.SSH != nil {
		sshConfig, err := sshhandler.NewConfig(&config.AuditLog, config.SSH, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create SSH config %w", err)
		}

		sshProxy = sshhandler.NewProxy(*sshConfig)
	}

	sessionrecorder.RegisterRecordedSessionMetrics(metrics.Namespace, registry)

	metricsServer := metrics.NewServer(metrics.Config{
		Port:     config.MetricsPort,
		Registry: registry,
	})

	return &Proxy{
		config:   config,
		registry: registry,
		logger:   logger,

		httpProxy:     httpProxy,
		sshProxy:      sshProxy,
		metricsServer: metricsServer,
	}, nil
}

func (p *Proxy) Start() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.config.Port))
	if err != nil {
		return err
	}

	p.listener = listener

	channels := make(map[connect.TransportProtocol]chan<- connect.Conn)

	var sshListener *connect.ProtocolListener

	if p.sshProxy != nil {
		sshChannel := make(chan connect.Conn)
		channels[connect.TransportSSH] = sshChannel
		sshListener = connect.NewProtocolListener(sshChannel, listener.Addr())
	}

	var httpListener *connect.ProtocolListener

	if p.httpProxy != nil {
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

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		p.logger.Info("Starting connect proxy", zap.Int("port", p.config.Port))

		err := connectListener.Serve(gCtx, listener)
		if err != nil {
			p.logger.Error("Connect proxy stopped with error", zap.Error(err))
		}

		return err
	})

	if p.sshProxy != nil {
		g.Go(func() error {
			p.logger.Info("Starting SSH proxy")

			err := p.sshProxy.Start(gCtx, sshListener)
			if err != nil {
				p.logger.Error("SSH proxy stopped with error", zap.Error(err))
			}

			return err
		})
	}

	if p.httpProxy != nil {
		g.Go(func() error {
			p.logger.Info("Starting HTTP proxy")

			err := p.httpProxy.Start(httpListener)
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}

			if err != nil {
				p.logger.Error("HTTP proxy stopped with error", zap.Error(err))
			}

			return err
		})
	}

	g.Go(func() error {
		p.logger.Info("Starting metrics server", zap.Int("port", p.config.MetricsPort))

		err := p.metricsServer.Start()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		if err != nil {
			p.logger.Error("Metrics server stopped with error", zap.Error(err))
		}

		return err
	})

	g.Go(func() error {
		<-gCtx.Done()
		p.shutdown() //nolint:contextcheck

		return nil
	})

	err = g.Wait()
	if err != nil {
		p.logger.Error("Proxy component error", zap.Error(err))
	}

	return err
}

func (p *Proxy) shutdown() {
	p.shutdownOnce.Do(func() {
		p.logger.Info("Starting graceful shutdown")

		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if p.listener != nil {
			if err := p.listener.Close(); err != nil {
				p.logger.Error("Failed to close TCP listener", zap.Error(err))
			}
		}

		if p.httpProxy != nil {
			if err := p.httpProxy.Shutdown(ctx); err != nil {
				p.logger.Error("Failed to shut down HTTP proxy", zap.Error(err))
			}
		}

		if p.sshProxy != nil {
			p.sshProxy.Shutdown(ctx)
		}

		if err := p.metricsServer.Shutdown(ctx); err != nil {
			p.logger.Error("Failed to shut down metrics server", zap.Error(err))
		}

		p.logger.Info("Graceful shutdown complete")
	})
}
