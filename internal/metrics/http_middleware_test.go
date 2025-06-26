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

func TestHTTPMetricsMiddleware(t *testing.T) {
	testCases := []struct {
		name           string
		setupRequest   func(*http.Request)
		expectedLabels map[string]map[string]string
	}{
		{
			name:         "HTTP Request",
			setupRequest: func(_ *http.Request) {}, // No special headers for regular HTTP
			expectedLabels: map[string]map[string]string{
				"twingate_gateway_http_requests_total": {
					"method": "get",
					"code":   "200",
				},
				"twingate_gateway_http_request_size_bytes": {
					"type":   "http",
					"method": "get",
					"code":   "200",
				},
				"twingate_gateway_http_response_size_bytes": {
					"type":   "http",
					"method": "get",
					"code":   "200",
				},
			},
		},
		{
			name: "WebSocket Request",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Connection", "upgrade")
				req.Header.Set("Sec-WebSocket-Protocol", "v5.channel.k8s.io")
			},
			expectedLabels: map[string]map[string]string{
				"twingate_gateway_http_requests_total": {
					"method": "get",
					"code":   "200",
				},
				"twingate_gateway_http_request_size_bytes": {
					"type":   "websocket",
					"method": "get",
					"code":   "200",
				},
				"twingate_gateway_http_response_size_bytes": {
					"type":   "websocket",
					"method": "get",
					"code":   "200",
				},
			},
		},
		{
			name: "SPDY Request",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Connection", "upgrade")
				req.Header.Set("Sec-WebSocket-Protocol", "SPDY/3.1+portforward.k8s.io")
			},
			expectedLabels: map[string]map[string]string{
				"twingate_gateway_http_requests_total": {
					"method": "get",
					"code":   "200",
				},
				"twingate_gateway_http_request_size_bytes": {
					"type":   "spdy",
					"method": "get",
					"code":   "200",
				},
				"twingate_gateway_http_response_size_bytes": {
					"type":   "spdy",
					"method": "get",
					"code":   "200",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testRegistry := prometheus.NewRegistry()

			server := httptest.NewServer(HTTPMetricsMiddleware(
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

			registeredLabels := extractLabelsFromMetrics(metricFamilies)
			assert.Equal(t, tc.expectedLabels, registeredLabels)
		})
	}
}

func extractLabelsFromMetrics(metricFamilies []*dto.MetricFamily) map[string]map[string]string {
	registeredLabels := make(map[string]map[string]string, len(metricFamilies))

	for _, mf := range metricFamilies {
		labels := mf.GetMetric()[0].GetLabel()
		for _, label := range labels {
			value, ok := registeredLabels[mf.GetName()]
			if !ok {
				value = make(map[string]string)
			}

			value[label.GetName()] = label.GetValue()
			registeredLabels[mf.GetName()] = value
		}
	}

	return registeredLabels
}
