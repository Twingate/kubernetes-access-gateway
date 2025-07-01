package metrics

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/httpstream/wsstream"
)

type HTTPMiddlewareConfig struct {
	Registry *prometheus.Registry
	Next     http.Handler
}

type metricsContextKey string

const httpMetricsContextKey metricsContextKey = "HTTP_CONTEXT"

func HTTPMetricsMiddleware(config HTTPMiddlewareConfig) http.HandlerFunc {
	httpRequestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "http_requests_total",
		Help:      "Total number of HTTP requests processed",
	}, []string{"type", "method", "code"})

	httpRequestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "Tracks the latencies for HTTP requests",
			Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
		},
		[]string{"type", "method", "code"},
	)

	httpRequestSizeBytes := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "http_request_size_bytes",
		Help:      "Size of incoming HTTP request in bytes",
		Buckets:   prometheus.ExponentialBuckets(100, 10, 6),
	}, []string{"type", "method", "code"})

	httpResponseSizeBytes := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "http_response_size_bytes",
		Help:      "Size of outgoing HTTP response in bytes",
		Buckets:   prometheus.ExponentialBuckets(100, 10, 6),
	}, []string{"type", "method", "code"},
	)

	config.Registry.MustRegister(httpRequestsTotal, httpRequestDuration, httpRequestSizeBytes, httpResponseSizeBytes)

	opts := promhttp.WithLabelFromCtx("type",
		func(ctx context.Context) string {
			if value, ok := ctx.Value(httpMetricsContextKey).(string); ok {
				return value
			}

			return "unknown"
		},
	)

	base := promhttp.InstrumentHandlerCounter(
		httpRequestsTotal,
		promhttp.InstrumentHandlerDuration(
			httpRequestDuration,
			promhttp.InstrumentHandlerRequestSize(
				httpRequestSizeBytes,
				promhttp.InstrumentHandlerResponseSize(
					httpResponseSizeBytes,
					config.Next,
					opts,
				),
				opts,
			),
			opts,
		),
	)

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		switch {
		case wsstream.IsWebSocketRequestWithTunnelingProtocol(r):
			ctx = context.WithValue(ctx, httpMetricsContextKey, "spdy")
		case httpstream.IsUpgradeRequest(r):
			ctx = context.WithValue(ctx, httpMetricsContextKey, "websocket")
		default:
			ctx = context.WithValue(ctx, httpMetricsContextKey, "http")
		}

		base.ServeHTTP(w, r.WithContext(ctx))
	}
}
