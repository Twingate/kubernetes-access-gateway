// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"k8sgateway/internal/metrics"
)

var (
	authenticationsTotal   *prometheus.CounterVec
	authenticationDuration *prometheus.HistogramVec
)

func RegisterHTTPConnectMetrics(registry *prometheus.Registry) {
	authenticationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connection_authentication_total",
		Help:      "Total number of client TCP connections authenticated via HTTP Connect",
	}, []string{"code"})
	authenticationDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connection_authentication_duration_seconds",
		Help:      "Duration of client TCP connections authenticated via HTTP Connect in seconds",
		Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
	}, []string{"code"})

	registry.MustRegister(authenticationsTotal, authenticationDuration)
}

func InstrumentHTTPConnect(validator Validator) func(req *http.Request, ekm []byte) (Info, error) {
	return func(req *http.Request, ekm []byte) (Info, error) {
		start := time.Now()

		connectInfo, err := validator.ParseConnect(req, ekm)
		code := http.StatusOK

		if err != nil {
			var httpErr *HTTPError
			if errors.As(err, &httpErr) {
				code = httpErr.Code
			} else {
				code = http.StatusBadRequest
			}
		}

		authenticationDuration.WithLabelValues(strconv.Itoa(code)).Observe(time.Since(start).Seconds())
		authenticationsTotal.WithLabelValues(strconv.Itoa(code)).Inc()

		return connectInfo, err
	}
}
