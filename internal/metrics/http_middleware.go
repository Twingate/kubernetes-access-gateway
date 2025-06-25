package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

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
	}, []string{"method", "code"})

	httpResponseSizeBytes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "http_response_size_bytes",
		Help:      "Size of outgoing HTTP response in bytes (only for audited requests)",
		Buckets:   []float64{100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000},
	}, []string{"method", "code"},
	)

	reg.MustRegister(httpRequestsTotal, httpRequestSizeBytes, httpResponseSizeBytes)
}

func HTTPMetricsMiddleware(reg *prometheus.Registry, handler http.Handler) http.HandlerFunc {
	initHTTPMetrics(reg)

	base := promhttp.InstrumentHandlerCounter(
		httpRequestsTotal,
		promhttp.InstrumentHandlerRequestSize(
			httpRequestSizeBytes,
			promhttp.InstrumentHandlerResponseSize(
				httpResponseSizeBytes,
				handler,
			),
		),
	)

	return base.ServeHTTP
}
