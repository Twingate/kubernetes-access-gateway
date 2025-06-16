package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/common/version"
	"regexp"
)

const ExporterName = "twingate_gateway"

// TCP Metrics
var (
	TCPActiveConnections prometheus.Gauge
)

func init() {
	TCPActiveConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: ExporterName,
		Subsystem: "tcp",
		Name:      "active_connections",
		Help:      "Number of active TCP connections",
	})
}

func InitMetricVars() {
	prometheus.MustRegister(TCPActiveConnections)
}

func SetBuildInfo() {
	buildInfo := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
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

	prometheus.MustRegister(buildInfo)
}

func SetGoCollector() {
	prometheus.Unregister(collectors.NewGoCollector())

	prometheus.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(
			collectors.MetricsScheduler,
			collectors.MetricsGC,
			collectors.GoRuntimeMetricsRule{
				Matcher: regexp.MustCompile("^/mycustomrule.*"),
			},
		),
	))
}
