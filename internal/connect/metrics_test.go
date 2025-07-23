// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8sgateway/internal/metrics/testutil"
)

func TestRecordMetrics(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	RegisterMetrics(testRegistry)

	RecordMetrics(time.Now(), 200)

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	labelsByMetric := testutil.ExtractLabelsFromMetrics(metricFamilies)
	expectedLabels := map[string]map[string]string{
		"twingate_gateway_tcp_connection_authentication_total": {
			"code": "200",
		},
		"twingate_gateway_tcp_connection_authentication_duration_seconds": {
			"code": "200",
		},
	}

	assert.Equal(t, expectedLabels, labelsByMetric)
}
