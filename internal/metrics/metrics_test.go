package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterMetricVars(t *testing.T) {
	InitMetricsCollectors()

	testRegistry := prometheus.NewRegistry()
	RegisterMetricVars(testRegistry)

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	expectedMetrics := []string{
		// Build Info Metric
		"twingate_gateway_build_info",
	}

	registeredMetrics := make([]string, len(metricFamilies))
	for i, mf := range metricFamilies {
		registeredMetrics[i] = mf.GetName()
	}

	assert.Subset(t, registeredMetrics, expectedMetrics)
}
