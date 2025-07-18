// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetConnectionCategory(t *testing.T) {
	testCases := []struct {
		name           string
		request        *http.Request
		expectedResult string
	}{
		{
			name:           "Healthcheck category",
			request:        httptest.NewRequest(http.MethodGet, healthCheckPath, nil),
			expectedResult: connectionCategoryHealth,
		},
		{
			name:           "Proxy category",
			request:        httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil),
			expectedResult: connectionCategoryProxy,
		},
		{
			name:           "Unknown category",
			request:        nil,
			expectedResult: connectionCategoryUnknown,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conn := newConnWithMetrics(&mockConn{})
			if tc.request != nil {
				conn.setConnectionCategory(tc.request)
			}

			assert.Equal(t, tc.expectedResult, conn.connectionCategory)
		})
	}
}

func TestProxyConnWithMetrics(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	registerConnectionMetrics(testRegistry)

	conn := newConnWithMetrics(&mockConn{})
	conn.setConnectionCategory(&http.Request{})

	err := conn.Close()
	require.NoError(t, err)

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	expectedLabels := map[string]map[string]string{
		"twingate_gateway_active_tcp_connections": {},
		"twingate_gateway_tcp_connections_total": {
			"conn_category": "proxy",
		},
		"twingate_gateway_tcp_connection_duration_seconds": {
			"conn_category": "proxy",
		},
	}

	labelsByMetric := make(map[string]map[string]string, len(metricFamilies))
	for _, family := range metricFamilies {
		labels := make(map[string]string)
		for _, label := range family.GetMetric()[0].GetLabel() {
			labels[label.GetName()] = label.GetValue()
		}

		labelsByMetric[family.GetName()] = labels
	}

	assert.Equal(t, expectedLabels, labelsByMetric)
}
