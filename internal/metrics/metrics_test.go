// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitMetricCollectors(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	registerCoreMetrics(testRegistry)

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	// Note that this list only contain a subset of Go and process metrics.
	// We want to make sure that the Go and process collectors are registered.
	expectedMetrics := []string{
		// Build Info Metric
		"twingate_gateway_build_info",
		// Go Metric
		"go_gc_duration_seconds",
		// Process Metric
		"process_cpu_seconds_total",
	}

	registeredMetrics := make([]string, len(metricFamilies))
	for i, mf := range metricFamilies {
		registeredMetrics[i] = mf.GetName()
	}

	assert.Subset(t, registeredMetrics, expectedMetrics)
}
