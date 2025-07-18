// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"k8sgateway/internal/metrics"
)

const (
	connectionCategoryUnknown = "unknown"
	connectionCategoryProxy   = "proxy"
	connectionCategoryHealth  = "health"
)

type ConnWithMetrics struct {
	net.Conn

	start              time.Time
	connectionCategory string
}

var (
	activeConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metrics.Namespace,
		Name:      "active_client_connections",
		Help:      "Number of currently active TCP connections",
	})
	connectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "client_connections_total",
		Help:      "Total number of TCP connections processed",
	}, []string{"conn_category"})
	connectionDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Name:      "client_connection_duration_seconds",
		Help:      "Duration of TCP connections in seconds",
		Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
	}, []string{"conn_category"})
)

func registerConnectionMetrics(registry *prometheus.Registry) {
	registry.MustRegister(activeConnections, connectionsTotal, connectionDuration)
}

func newConnWithMetrics(conn net.Conn) *ConnWithMetrics {
	activeConnections.Inc()

	return &ConnWithMetrics{
		Conn:               conn,
		start:              time.Now(),
		connectionCategory: connectionCategoryUnknown,
	}
}

func (p *ConnWithMetrics) Close() error {
	err := p.Conn.Close()

	activeConnections.Dec()
	connectionsTotal.WithLabelValues(p.connectionCategory).Inc()
	connectionDuration.WithLabelValues(p.connectionCategory).Observe(time.Since(p.start).Seconds())

	return err
}

func (p *ConnWithMetrics) setConnectionCategory(req *http.Request) {
	if isHealthCheckRequest(req) {
		p.connectionCategory = connectionCategoryHealth
	} else {
		p.connectionCategory = connectionCategoryProxy
	}
}
