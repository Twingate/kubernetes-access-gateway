// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"k8sgateway/internal/metrics"
)

var (
	connectTotal    *prometheus.CounterVec
	connectDuration *prometheus.HistogramVec
)

func RegisterConnectMetrics(registry *prometheus.Registry) {
	connectTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connection_authentication_total",
		Help:      "Total number of client TCP connections authenticated via HTTP Connect",
	}, []string{"code"})
	connectDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connection_authentication_duration_seconds",
		Help:      "Duration of client TCP connections authenticated via HTTP Connect in seconds",
		Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
	}, []string{"code"})

	registry.MustRegister(connectTotal, connectDuration)
}

func RecordConnectDuration(start time.Time, code string) {
	connectDuration.WithLabelValues(code).Observe(time.Since(start).Seconds())
}

func RecordConnectTotal(code string) {
	connectTotal.WithLabelValues(code).Inc()
}
