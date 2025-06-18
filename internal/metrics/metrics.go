package metrics

import (
	"fmt"
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

func Start(config Config) {
	logger := config.Logger
	registry := config.Registry

	initMetricCollectors(registry)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
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

	reg.MustRegister(buildInfo, goCollector, processCollector)
}
