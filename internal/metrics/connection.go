// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	errorTypeRead  = "read"
	errorTypeWrite = "write"
	errorTypeClose = "close"
)

const (
	connectionTypeUnknown     = "unknown"
	connectionTypeProxy       = "proxy"
	connectionTypeHealthcheck = "health"
)

const HealthCheckPath = "/healthz"

type ProxyConnWithMetrics struct {
	net.Conn

	start          time.Time
	connectionType string
}

var (
	activeConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "active_client_connections",
		Help:      "Number of currently active client connections",
	})
	connectionDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "client_connection_duration_seconds",
		Help:      "Duration of TCP connections in seconds",
		Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
	}, []string{"conn_type"})
	connectionError = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "client_connection_errors_total",
		Help:      "Total number of client connection errors",
	}, []string{"conn_type", "type"})
)

func registerConnectionMetrics(registry *prometheus.Registry) {
	registry.MustRegister(activeConnections, connectionDuration, connectionError)
}

func NewProxyConnWithMetrics(conn net.Conn) *ProxyConnWithMetrics {
	activeConnections.Inc()

	return &ProxyConnWithMetrics{
		Conn:           conn,
		start:          time.Now(),
		connectionType: connectionTypeUnknown,
	}
}

func (p *ProxyConnWithMetrics) SetConnectionType(req *http.Request) {
	if req.Method == http.MethodGet && req.URL.Path == HealthCheckPath {
		p.connectionType = connectionTypeHealthcheck
	} else {
		p.connectionType = connectionTypeProxy
	}
}

func (p *ProxyConnWithMetrics) Read(b []byte) (int, error) {
	n, err := p.Conn.Read(b)
	if err != nil && !errors.Is(err, io.EOF) {
		connectionError.WithLabelValues(p.connectionType, errorTypeRead).Inc()
	}

	return n, err
}

func (p *ProxyConnWithMetrics) Write(b []byte) (int, error) {
	n, err := p.Conn.Write(b)
	if err != nil {
		connectionError.WithLabelValues(p.connectionType, errorTypeWrite).Inc()
	}

	return n, err
}

func (p *ProxyConnWithMetrics) Close() error {
	err := p.Conn.Close()
	if err != nil {
		connectionError.WithLabelValues(p.connectionType, errorTypeClose).Inc()
	}

	activeConnections.Dec()
	connectionDuration.WithLabelValues(p.connectionType).Observe(time.Since(p.start).Seconds())

	return err
}
