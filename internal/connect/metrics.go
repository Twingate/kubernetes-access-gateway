// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"k8sgateway/internal/metrics"
)

var (
	connectTotal    *prometheus.CounterVec
	connectDuration *prometheus.HistogramVec
)

func RegisterMetrics(registry *prometheus.Registry) {
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

	registry.MustRegister(connectTotal, connectDuration)
}

func RecordMetrics(start time.Time, code int) {
	codeStr := strconv.Itoa(code)
	connectDuration.WithLabelValues(codeStr).Observe(time.Since(start).Seconds())
	connectTotal.WithLabelValues(codeStr).Inc()
}
