// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dto "github.com/prometheus/client_model/go"
)

func TestIsSpdyRequest(t *testing.T) {
	tests := []struct {
		name         string
		newRequestFn func() *http.Request
		expected     bool
	}{
		{
			name: "SPDY request",
			newRequestFn: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Upgrade", "spdy/3.1")
				r.Header.Set("Connection", "upgrade")

				return r
			},
			expected: true,
		},
		{
			name: "Websocket request",
			newRequestFn: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Connection", "upgrade")

				return r
			},
			expected: false,
		},
		{
			name: "HTTP request",
			newRequestFn: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)

				return r
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSpdyRequest(tt.newRequestFn())
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHTTPMiddleware(t *testing.T) {
	testCases := []struct {
		name                string
		setupRequest        func(*http.Request)
		expectedRequestType string
	}{
		{
			name:                "HTTP Request",
			setupRequest:        func(_ *http.Request) {}, // No special headers for regular HTTP
			expectedRequestType: "http",
		},
		{
			name: "WebSocket Request",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Connection", "upgrade")
			},
			expectedRequestType: "websocket",
		},
		{
			name: "SPDY Request",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Upgrade", "spdy/3.1")
				req.Header.Set("Connection", "upgrade")
			},
			expectedRequestType: "spdy",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testRegistry := prometheus.NewRegistry()

			server := httptest.NewServer(HTTPMiddleware(
				HTTPMiddlewareConfig{
					Registry: testRegistry,
					Next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusOK)
					}),
				},
			))
			defer server.Close()

			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			require.NoError(t, err, "failed to create request")

			tc.setupRequest(req)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err, "failed to send request")
			defer resp.Body.Close()

			metricFamilies, err := testRegistry.Gather()
			require.NoError(t, err)

			labelsByMetric := extractLabelsFromMetrics(metricFamilies)
			expectedLabels := map[string]map[string]string{
				"twingate_gateway_http_requests_total": {
					"type":   tc.expectedRequestType,
					"method": "get",
					"code":   "200",
				},
				"twingate_gateway_http_active_requests": {
					"type": tc.expectedRequestType,
				},
				"twingate_gateway_http_request_duration_seconds": {
					"type":   tc.expectedRequestType,
					"method": "get",
					"code":   "200",
				},
				"twingate_gateway_http_request_size_bytes": {
					"type":   tc.expectedRequestType,
					"method": "get",
					"code":   "200",
				},
				"twingate_gateway_http_response_size_bytes": {
					"type":   tc.expectedRequestType,
					"method": "get",
					"code":   "200",
				},
			}
			assert.Equal(t, expectedLabels, labelsByMetric)
		})
	}
}

func extractLabelsFromMetrics(metricFamilies []*dto.MetricFamily) map[string]map[string]string {
	labelsByMetric := make(map[string]map[string]string, len(metricFamilies))

	for _, family := range metricFamilies {
		labels := make(map[string]string)
		for _, label := range family.GetMetric()[0].GetLabel() {
			labels[label.GetName()] = label.GetValue()
		}

		labelsByMetric[family.GetName()] = labels
	}

	return labelsByMetric
}
