package metrics

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/util/httpstream/wsstream"
)

type RoundTripperMiddlewareConfig struct {
	Registry *prometheus.Registry
	Next     http.RoundTripper
}

func RoundTripperMiddleware(config RoundTripperMiddlewareConfig) promhttp.RoundTripperFunc {
	requestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "api_server_requests_total",
		Help:      "Total number of requests from Gateway to API Server processed",
	}, []string{"type", "method", "code"})

	activeRequests := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "api_server_active_requests",
		Help:      "Number of currently active requests from Gateway to API Server",
	}, []string{"type"})

	requestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "api_server_request_duration_seconds",
			Help:      "Latencies of requests from Gateway to API Server in seconds",
			Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
		}, []string{"type", "method", "code"})

	config.Registry.MustRegister(requestsTotal, activeRequests, requestDuration)

	opts := promhttp.WithLabelFromCtx(labelRequestType, getRequestContextValue)

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

	return promhttp.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		ctx := r.Context()

		switch {
		case isSpdyRequest(r):
			ctx = context.WithValue(ctx, contextKey{}, requestTypeSPDY)
		case wsstream.IsWebSocketRequest(r):
			ctx = context.WithValue(ctx, contextKey{}, requestTypeWebsocket)
		default:
			ctx = context.WithValue(ctx, contextKey{}, requestTypeHTTP)
		}

		return base.RoundTrip(r.WithContext(ctx))
	})
}

func instrumentRoundTripperInFlight(activeRequests *prometheus.GaugeVec, next http.RoundTripper) promhttp.RoundTripperFunc {
	return promhttp.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		requestType := getRequestContextValue(r.Context())

		activeRequests.WithLabelValues(requestType).Inc()
		defer activeRequests.WithLabelValues(requestType).Dec()

		return next.RoundTrip(r)
	})
}
