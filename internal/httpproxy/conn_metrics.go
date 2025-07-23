// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"k8sgateway/internal/metrics"
)

const (
	connCategoryUnknown = "unknown"
	connCategoryProxy   = "proxy"
	connCategoryHealth  = "health"
)

type connWithMetrics struct {
	net.Conn

	start time.Time
	once  sync.Once
}

var (
	activeConn   prometheus.Gauge
	connTotal    *prometheus.CounterVec
	connDuration *prometheus.HistogramVec
)

func registerConnMetrics(registry *prometheus.Registry) {
	activeConn = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metrics.Namespace,
		Name:      "active_tcp_connections",
		Help:      "Number of currently active client TCP connections",
	})
	connTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connections_total",
		Help:      "Total number of client TCP connections processed",
	}, []string{"connection_category"})
	connDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connection_duration_seconds",
		Help:      "Duration of client TCP connections in seconds",
		Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
	}, []string{"connection_category"})

	registry.MustRegister(activeConn, connTotal, connDuration)
}

func newConnWithMetrics(conn net.Conn) *connWithMetrics {
	activeConn.Inc()

	return &connWithMetrics{
		Conn:  conn,
		start: time.Now(),
	}
}

func (p *connWithMetrics) Close() error {
	err := p.Conn.Close()

	defer func() {
		p.once.Do(func() {
			connCategory := p.Conn.(*ProxyConn).connCategory

			activeConn.Dec()
			connTotal.WithLabelValues(connCategory).Inc()
			connDuration.WithLabelValues(connCategory).Observe(time.Since(p.start).Seconds())
		})
	}()

	return err
}
