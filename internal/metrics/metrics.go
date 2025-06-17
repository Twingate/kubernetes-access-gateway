package metrics

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"go.uber.org/zap"
)

const ExporterName = "twingate_gateway"

type Config struct {
	Port string
}

var (
	buildInfo        prometheus.GaugeFunc
	goCollector      prometheus.Collector
	processCollector prometheus.Collector
)

func InitMetricsCollectors() {
	buildInfo = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: ExporterName,
		Name:      "build_info",
		Help:      "A metric with a constant '1' value labeled by version, goversion, goos and goarch from which Twingate Kubernetes Access Gateway was built.",
		ConstLabels: prometheus.Labels{
			"version":   version.Version,
			"goversion": version.GoVersion,
			"goos":      version.GoOS,
			"goarch":    version.GoArch,
		},
	}, func() float64 { return 1 })

	goCollector = collectors.NewGoCollector()

	processCollector = collectors.NewProcessCollector(
		collectors.ProcessCollectorOpts{
			Namespace: ExporterName,
		},
	)
}

func RegisterMetricVars(reg prometheus.Registerer) {
	// Unregister the default GoCollector
	reg.Unregister(collectors.NewGoCollector())

	reg.MustRegister(buildInfo, goCollector, processCollector)
}

func Start(config Config) {
	logger := zap.S()

	InitMetricsCollectors()

	registry := prometheus.NewRegistry()
	RegisterMetricVars(registry)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	metricsServer := &http.Server{
		Addr:    fmt.Sprintf(":%v", config.Port),
		Handler: mux,
	}

	logger.Infof("Starting metrics server on: %v", config.Port)

	if err := metricsServer.ListenAndServe(); err != nil {
		logger.Fatalf("Failed to start metrics server: %v", err)
	}
}
