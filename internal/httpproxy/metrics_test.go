// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"k8sgateway/internal/metrics/testutil"
)

func TestProxyConnMetrics(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics := registerProxyConnMetrics(testRegistry)

	proxyConnMetrics := &proxyConnMetricsTracker{
		connCategory: connCategoryProxy,
		metrics:      metrics,
	}

	proxyConnMetrics.startMeasure()

	proxyConnMetrics.recordConnMetrics()
	proxyConnMetrics.recordConnectAuthenticationMetrics(200)

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	labelsByMetric := testutil.ExtractLabelsFromMetrics(metricFamilies)
	expectedLabels := map[string]map[string]string{
		"twingate_gateway_active_tcp_connections": {},
		"twingate_gateway_tcp_connections_total": {
			"connection_category": "proxy",
		},
		"twingate_gateway_tcp_connection_duration_seconds": {
			"connection_category": "proxy",
		},
		"twingate_gateway_tcp_connection_authentication_total": {
			"code": "200",
		},
		"twingate_gateway_tcp_connection_authentication_duration_seconds": {
			"code": "200",
		},
	}

	assert.Equal(t, expectedLabels, labelsByMetric)

	count := promtestutil.ToFloat64(metrics.connTotal)
	assert.Equal(t, 1, int(count))

	histogram := testutil.GetHistogram("twingate_gateway_tcp_connection_duration_seconds", metricFamilies)
	require.NotNil(t, histogram)
	assert.Equal(t, uint64(1), histogram.GetSampleCount())
	assert.Positive(t, histogram.GetSampleSum())

	count = promtestutil.ToFloat64(metrics.connectTotal)
	assert.Equal(t, 1, int(count))

	histogram = testutil.GetHistogram("twingate_gateway_tcp_connection_authentication_duration_seconds", metricFamilies)
	require.NotNil(t, histogram)
	assert.Positive(t, histogram.GetSampleSum())
}

func TestProxyConnMetrics_WithoutStartMeasure(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics := registerProxyConnMetrics(testRegistry)

	proxyConnMetrics := &proxyConnMetricsTracker{
		connCategory: connCategoryProxy,
		metrics:      metrics,
	}

	proxyConnMetrics.recordConnMetrics()
	proxyConnMetrics.recordConnectAuthenticationMetrics(200)

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	labelsByMetric := testutil.ExtractLabelsFromMetrics(metricFamilies)
	expectedLabels := map[string]map[string]string{
		"twingate_gateway_active_tcp_connections": {},
	}

	assert.Equal(t, expectedLabels, labelsByMetric)
}
