// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundTripperMiddleware(t *testing.T) {
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

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tc.setupRequest(req)

			middleware := RoundTripperMiddleware(RoundTripperMiddlewareConfig{
				Registry: testRegistry,
				Next: promhttp.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
				}),
			})

			resp, err := middleware.RoundTrip(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			metricFamilies, err := testRegistry.Gather()
			require.NoError(t, err)

			labelsByMetric := extractLabelsFromMetrics(metricFamilies)
			expectedLabels := map[string]map[string]string{
				"twingate_gateway_api_server_requests_total": {
					"type":   tc.expectedRequestType,
					"method": "get",
					"code":   "200",
				},
				"twingate_gateway_api_server_active_requests": {
					"type": tc.expectedRequestType,
				},
				"twingate_gateway_api_server_request_duration_seconds": {
					"type":   tc.expectedRequestType,
					"method": "get",
					"code":   "200",
				},
			}
			assert.Equal(t, expectedLabels, labelsByMetric)
		})
	}
}
