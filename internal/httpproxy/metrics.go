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

var (
	activeConn   prometheus.Gauge
	connTotal    *prometheus.CounterVec
	connDuration *prometheus.HistogramVec

	connectTotal    *prometheus.CounterVec
	connectDuration *prometheus.HistogramVec
)

func registerProxyConnMetrics(registry *prometheus.Registry) {
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

	connectTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connection_authentication_total",
		Help:      "Total number of client TCP connections authenticated via HTTP Connect",
	}, []string{"code"})
	connectDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connection_authentication_duration_seconds",
		Help:      "Duration of client TCP connections authenticated via HTTP Connect in seconds",
		Buckets:   prometheus.DefBuckets,
	}, []string{"code"})

	registry.MustRegister(activeConn, connTotal, connDuration, connectTotal, connectDuration)
}

type proxyConnMetrics struct {
	start        time.Time
	connCategory string
}

func (m *proxyConnMetrics) startMeasure() {
	m.start = time.Now()

	activeConn.Inc()
}

func (m *proxyConnMetrics) stopMeasureConn() {
	if m.start.IsZero() {
		return
	}

	activeConn.Dec()
	connTotal.WithLabelValues(m.connCategory).Inc()
	connDuration.WithLabelValues(m.connCategory).Observe(time.Since(m.start).Seconds())
}

func (m *proxyConnMetrics) stopMeasureConnect(code int) {
	if m.start.IsZero() {
		return
	}

	codeStr := strconv.Itoa(code)

	connectDuration.WithLabelValues(codeStr).Observe(time.Since(m.start).Seconds())
	connectTotal.WithLabelValues(codeStr).Inc()
}
