// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type RoundTripperConfig struct {
	Registry *prometheus.Registry
	Next     http.RoundTripper
}

func RoundTripper(config RoundTripperConfig) promhttp.RoundTripperFunc {
	requestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "api_server_requests_total",
		Help:      "Total number of requests from Gateway to API Server processed",
	}, []string{"type", "method", "code"})

	activeRequests := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "api_server_active_requests",
		Help:      "Number of currently active requests from Gateway to API Server",
	}, []string{"type"})

	requestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "api_server_request_duration_seconds",
			Help:      "Measures the initial HTTP request-response latency between Gateway and API Server in seconds. For HTTP streaming, WebSocket, and SPDY connections, this metric captures only the setup time and not the duration of the data transfer.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"type", "method", "code"})

	config.Registry.MustRegister(requestsTotal, activeRequests, requestDuration)

	opts := promhttp.WithLabelFromCtx(labelRequestType, getRequestTypeFromContext)

	base := promhttp.InstrumentRoundTripperCounter(
		requestsTotal,
		instrumentRoundTripperInFlight(
			activeRequests,
			promhttp.InstrumentRoundTripperDuration(
				requestDuration,
				config.Next,
				opts,
			),
		),
		opts,
	)

	return func(r *http.Request) (*http.Response, error) {
		return base.RoundTrip(requestWithTypeContext(r))
	}
}

func instrumentRoundTripperInFlight(activeRequests *prometheus.GaugeVec, next http.RoundTripper) promhttp.RoundTripperFunc {
	return func(r *http.Request) (*http.Response, error) {
		requestType := getRequestTypeFromContext(r.Context())

		activeRequests.WithLabelValues(requestType).Inc()
		defer activeRequests.WithLabelValues(requestType).Dec()

		return next.RoundTrip(r)
	}
}
