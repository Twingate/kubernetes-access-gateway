package metrics

import (
	"context"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/httpstream/spdy"
	"k8s.io/apimachinery/pkg/util/httpstream/wsstream"
)

// Metric label names.
const (
	labelRequestType = "type"
)

// Request type values.
const (
	requestTypeHTTP      = "http"
	requestTypeWebsocket = "websocket"
	requestTypeSPDY      = "spdy"
	requestTypeUnknown   = "unknown"
)

type HTTPMiddlewareConfig struct {
	Registry *prometheus.Registry
	Next     http.Handler
}

type contextKey struct{}

func HTTPMiddleware(config HTTPMiddlewareConfig) http.HandlerFunc {
	requestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "http_requests_total",
		Help:      "Total number of HTTP requests processed",
	}, []string{"type", "method", "code"})

	requestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "Latencies of HTTP requests in seconds",
			Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
		}, []string{"type", "method", "code"})

	requestSizeBytes := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "http_request_size_bytes",
		Help:      "Size of incoming HTTP request in bytes",
		Buckets:   prometheus.ExponentialBuckets(100, 10, 6),
	}, []string{"type", "method", "code"})

	responseSizeBytes := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "http_response_size_bytes",
		Help:      "Size of outgoing HTTP response in bytes",
		Buckets:   prometheus.ExponentialBuckets(100, 10, 6),
	}, []string{"type", "method", "code"},
	)

	config.Registry.MustRegister(requestsTotal, requestDuration, requestSizeBytes, responseSizeBytes)

	opts := promhttp.WithLabelFromCtx(labelRequestType,
		func(ctx context.Context) string {
			if value, ok := ctx.Value(contextKey{}).(string); ok {
				return value
			}

			return requestTypeUnknown
		},
	)

	base := promhttp.InstrumentHandlerCounter(
		requestsTotal,
		promhttp.InstrumentHandlerDuration(
			requestDuration,
			promhttp.InstrumentHandlerRequestSize(
				requestSizeBytes,
				promhttp.InstrumentHandlerResponseSize(
					responseSizeBytes,
					config.Next,
					opts,
				),
				opts,
			),
			opts,
		),
		opts,
	)

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		switch {
		case isSpdyRequest(r):
			ctx = context.WithValue(ctx, contextKey{}, requestTypeSPDY)
		case wsstream.IsWebSocketRequest(r):
			ctx = context.WithValue(ctx, contextKey{}, requestTypeWebsocket)
		default:
			ctx = context.WithValue(ctx, contextKey{}, requestTypeHTTP)
		}

		base.ServeHTTP(w, r.WithContext(ctx))
	}
}

func isSpdyRequest(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get(httpstream.HeaderUpgrade), spdy.HeaderSpdy31) {
		return false
	}

	return httpstream.IsUpgradeRequest(r)
}
