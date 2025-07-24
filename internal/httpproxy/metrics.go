// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"k8sgateway/internal/metrics"
)

const (
	connCategoryUnknown = "unknown"
	connCategoryProxy   = "proxy"
	connCategoryHealth  = "health"
)

type proxyConnMetrics struct {
	activeConn   prometheus.Gauge
	connTotal    *prometheus.CounterVec
	connDuration *prometheus.HistogramVec

	connectTotal    *prometheus.CounterVec
	connectDuration *prometheus.HistogramVec
}

func registerProxyConnMetrics(registry *prometheus.Registry) *proxyConnMetrics {
	activeConn := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metrics.Namespace,
		Name:      "active_tcp_connections",
		Help:      "Number of currently active client TCP connections",
	})
	connTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connections_total",
		Help:      "Total number of client TCP connections processed",
	}, []string{"connection_category"})
	connDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connection_duration_seconds",
		Help:      "Duration of client TCP connections in seconds",
		Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
	}, []string{"connection_category"})
	connectTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connection_authentication_total",
		Help:      "Total number of client TCP connections authenticated via HTTP Connect",
	}, []string{"code"})
	connectDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connection_authentication_duration_seconds",
		Help:      "Duration of client TCP connections authenticated via HTTP Connect in seconds",
		Buckets:   prometheus.DefBuckets,
	}, []string{"code"})

	registry.MustRegister(activeConn, connTotal, connDuration, connectTotal, connectDuration)

	return &proxyConnMetrics{
		activeConn:      activeConn,
		connTotal:       connTotal,
		connDuration:    connDuration,
		connectTotal:    connectTotal,
		connectDuration: connectDuration,
	}
}

type proxyConnMetricsTracker struct {
	metrics      *proxyConnMetrics
	start        time.Time
	connCategory string
}

func newProxyConnMetrics(connCategory string, proxyConnMetrics *proxyConnMetrics) *proxyConnMetricsTracker {
	return &proxyConnMetricsTracker{
		connCategory: connCategory,
		metrics:      proxyConnMetrics,
	}
}

func (p *proxyConnMetricsTracker) startMeasure() {
	p.start = time.Now()
	p.metrics.activeConn.Inc()
}

func (p *proxyConnMetricsTracker) recordConnMetrics() {
	if p.start.IsZero() {
		return
	}

	p.metrics.activeConn.Dec()
	p.metrics.connTotal.WithLabelValues(p.connCategory).Inc()
	p.metrics.connDuration.WithLabelValues(p.connCategory).Observe(time.Since(p.start).Seconds())
}

func (p *proxyConnMetricsTracker) recordConnectAuthenticationMetrics(code int) {
	if p.start.IsZero() {
		return
	}

	codeStr := strconv.Itoa(code)
	p.metrics.connectDuration.WithLabelValues(codeStr).Observe(time.Since(p.start).Seconds())
	p.metrics.connectTotal.WithLabelValues(codeStr).Inc()
}
