// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8sgateway/internal/metrics/testutil"
)

func TestProxyConnWithMetrics(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	registerConnMetrics(testRegistry)

	conn := newConnWithMetrics(&mockConn{})
	conn.connCategory = connCategoryProxy

	err := conn.Close()
	require.NoError(t, err)

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
	}

	assert.Equal(t, expectedLabels, labelsByMetric)
}
