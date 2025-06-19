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

const namespace = "twingate_gateway"

type Config struct {
	Port   string
	Logger *zap.SugaredLogger
}

func Start(config Config) error {
	logger := config.Logger

	registry := prometheus.NewRegistry()
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

	return server.ListenAndServe()
}

func initMetricCollectors(reg *prometheus.Registry) {
	buildInfo := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "build_info",
		Help:      "A metric with a constant '1' value labeled by version, goversion, goos and goarch from which Twingate Kubernetes Access Gateway was built.",
		ConstLabels: prometheus.Labels{
			"version":   version.Version,
			"goversion": runtime.Version(),
			"goos":      runtime.GOOS,
			"goarch":    runtime.GOARCH,
		},
	}, func() float64 { return 1 })

	goCollector := collectors.NewGoCollector()

	processCollector := collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})

	reg.MustRegister(buildInfo, goCollector, processCollector)
}
