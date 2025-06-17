package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterMetricVars(t *testing.T) {
	InitMetricsCollectors()

	registry := prometheus.NewRegistry()
	RegisterMetricVars(registry)

	metricFamilies, err := registry.Gather()
	require.NoError(t, err)

	expectedMetrics := []string{
		// Build Info Metric
		"twingate_gateway_build_info",

		// Go Metrics
		"go_gc_duration_seconds",

		// Go Process Metrics
		"twingate_gateway_process_cpu_seconds_total",

	}

	registeredMetrics := make([]string, len(metricFamilies))
	for i, mf := range metricFamilies {
		registeredMetrics[i] = mf.GetName()
	}

	assert.Subset(t, registeredMetrics, expectedMetrics)
}
