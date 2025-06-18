package metrics

import (
	"fmt"
	"math"
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"k8sgateway/internal/version"
)

const Namespace = "twingate_gateway"

type Config struct {
	Port     string
	Logger   *zap.SugaredLogger
	Registry *prometheus.Registry
}

var (
	buildInfo        prometheus.GaugeFunc
	goCollector      prometheus.Collector
	processCollector prometheus.Collector
)

var (
	APIConnectionsActive            prometheus.Gauge
	APIConnectionsDurationSeconds   prometheus.Histogram
	ClientConnectionsActive         prometheus.Gauge
	ClientConnectionDurationSeconds prometheus.Histogram
	ClientConnectionErrorsTotal     *prometheus.CounterVec
	ClientAuthenticationsTotal      *prometheus.CounterVec
	HTTPRequestsTotal               *prometheus.CounterVec
	HTTPRequestSizeBytes            *prometheus.HistogramVec
	HTTPResponseSizeBytes           prometheus.Histogram
	WebsocketSessionsActive         prometheus.Gauge
	WebsocketSessionDurationSeconds prometheus.Histogram
	WebsocketSessionErrorsTotal     *prometheus.CounterVec
)

func Start(config Config) {
	logger := config.Logger
	registry := config.Registry

	initMetricCollectors(registry)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry}))
	server := &http.Server{
		// G112 - Protect against Slowloris attack
		ReadHeaderTimeout: 5 * time.Second,

		Addr:    fmt.Sprintf(":%v", config.Port),
		Handler: mux,
	}

	logger.Infof("Starting metrics server on: %v", config.Port)

	if err := server.ListenAndServe(); err != nil {
		logger.Fatalf("Failed to start metrics server: %v", err)
	}
}

func initMetricCollectors(reg *prometheus.Registry) {
	buildInfo = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "build_info",
		Help:      "A metric with a constant '1' value labeled by version, goversion, goos and goarch from which Twingate Kubernetes Access Gateway was built.",
		ConstLabels: prometheus.Labels{
			"version":   version.Version,
			"goversion": runtime.Version(),
			"goos":      runtime.GOOS,
			"goarch":    runtime.GOARCH,
		},
	}, func() float64 { return 1 })

	goCollector = collectors.NewGoCollector()

	processCollector = collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})

	// region API Server Metrics.
	APIConnectionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "api_connections_active",
		Help:      "Number of currently active API server connections",
	})

	APIConnectionsDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "api_connection_duration_seconds",
		Help:      "Duration of API server connections in seconds",
		Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, math.Inf(1)},
	})
	// endregion

	// region Client Metrics.
	ClientConnectionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "client_connections_active",
		Help:      "Number of currently active client connections",
	})

	ClientConnectionDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "client_connection_duration_seconds",
		Help:      "Duration of TCP connections in seconds",
		Buckets:   []float64{.1, .25, .5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, math.Inf(1)},
	})

	ClientConnectionErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "client_connection_errors_total",
		Help:      "Total number of client connection establishment failures",
	}, []string{"error_type"})

	ClientAuthenticationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "client_authentications_total",
		Help:      "Total number of authentication attempts via CONNECT message",
	}, []string{"status_code"})
	// endregion

	// region HTTP Metrics.
	HTTPRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "http_requests_total",
		Help:      "Total number of HTTP requests processed",
	}, []string{"type", "method", "status"})

	HTTPRequestSizeBytes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "http_request_size_bytes",
		Help:      "Size of incoming HTTP request in bytes",
		Buckets:   []float64{100, 1000, 10000, 100000, 1000000, 10000000, math.Inf(1)},
	}, []string{"type"})

	HTTPResponseSizeBytes = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "http_response_size_bytes",
		Help:      "Size of outgoing HTTP response in bytes (only for audited requests)",
		Buckets:   []float64{100, 1000, 10000, 100000, 1000000, 10000000, math.Inf(1)},
	})
	// endregion

	// region Websocket Metrics.
	WebsocketSessionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "websocket_sessions_active",
		Help:      "Total number of currently active WebSocket sessions",
	})

	WebsocketSessionDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "websocket_session_duration_seconds",
		Help:      "Duration of WebSocket sessions in seconds",
		Buckets:   []float64{1, 5, 10, 30, 60, 300, 600, 1800, 3600, math.Inf(1)},
	})

	WebsocketSessionErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "websocket_session_errors_total",
		Help:      "Total number of WebSocket session failures",
	}, []string{"error_type"})
	// endregion

	reg.MustRegister(
		buildInfo,
		goCollector,
		processCollector,
		APIConnectionsActive,
		APIConnectionsDurationSeconds,
		ClientConnectionsActive,
		ClientConnectionDurationSeconds,
		ClientConnectionErrorsTotal,
		ClientAuthenticationsTotal,
		HTTPRequestsTotal,
		HTTPRequestSizeBytes,
		HTTPResponseSizeBytes,
		WebsocketSessionsActive,
		WebsocketSessionDurationSeconds,
		WebsocketSessionErrorsTotal,
	)
}
