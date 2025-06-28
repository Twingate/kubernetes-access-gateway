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

var (
	httpRequestsTotal     *prometheus.CounterVec
	httpRequestSizeBytes  *prometheus.HistogramVec
	httpResponseSizeBytes *prometheus.HistogramVec
)

func initHTTPMetrics(reg *prometheus.Registry) {
	httpRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "http_requests_total",
		Help:      "Total number of HTTP requests processed",
	}, []string{"method", "code"})

	httpRequestSizeBytes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "http_request_size_bytes",
		Help:      "Size of incoming HTTP request in bytes",
		Buckets:   []float64{100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000},
	}, []string{"type", "method", "code"})

	httpResponseSizeBytes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "http_response_size_bytes",
		Help:      "Size of outgoing HTTP response in bytes (only for audited requests)",
		Buckets:   []float64{100, 1_000, 10_000, 100_000, 1000_000, 10_000_000},
	}, []string{"type", "method", "code"},
	)

	reg.MustRegister(httpRequestsTotal, httpRequestSizeBytes, httpResponseSizeBytes)
}

func HTTPMetricsMiddleware(config HTTPMiddlewareConfig) http.HandlerFunc {
	initHTTPMetrics(config.Registry)

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
		promhttp.InstrumentHandlerRequestSize(
			httpRequestSizeBytes,
			promhttp.InstrumentHandlerResponseSize(
				httpResponseSizeBytes,
				config.Next,
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
