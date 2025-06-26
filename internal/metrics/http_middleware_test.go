package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPMetricsMiddleware(t *testing.T) {
	testRegistry := prometheus.NewRegistry()

	server := httptest.NewServer(HTTPMetricsMiddleware(testRegistry,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	))
	defer server.Close()

	getReq, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err, "Failed to create request")

	// Make a dummy GET request to trigger the middleware
	getResp, err := http.DefaultClient.Do(getReq)
	require.NoError(t, err, "failed to send request")
	defer getResp.Body.Close()

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	registeredLabels := make(map[string]map[string]string, len(metricFamilies))

	for _, mf := range metricFamilies {
		labels := mf.GetMetric()[0].GetLabel()
		for _, label := range labels {
			val, ok := registeredLabels[mf.GetName()]
			if !ok {
				val = make(map[string]string)
			}

			val[label.GetName()] = label.GetValue()
			registeredLabels[mf.GetName()] = val
		}
	}

	assert.Equal(t, map[string]map[string]string{
		"twingate_gateway_http_requests_total": {
			"method": "get",
			"code":   "200",
		},
		"twingate_gateway_http_request_size_bytes": {
			"type":   "rest",
			"method": "get",
			"code":   "200",
		},
		"twingate_gateway_http_response_size_bytes": {
			"type":   "rest",
			"method": "get",
			"code":   "200",
		},
	}, registeredLabels)
}

func TestHTTPMetricsMiddleware_WebSocketRequest(t *testing.T) {
	testRegistry := prometheus.NewRegistry()

	server := httptest.NewServer(
		HTTPMetricsMiddleware(testRegistry,
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		),
	)
	defer server.Close()

	wsReq, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err, "failed to create websocket request")
	wsReq.Header.Set("Upgrade", "websocket")
	wsReq.Header.Set("Connection", "upgrade")
	wsReq.Header.Set("Sec-WebSocket-Protocol", "SPDY/3.1+portforward.k8s.io")

	// Make a dummy WebSocket upgrade request to trigger the middleware
	wsResp, err := http.DefaultClient.Do(wsReq)
	require.NoError(t, err, "failed to send websocket request")
	defer wsResp.Body.Close()

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	registeredLabels := make(map[string]map[string]string, len(metricFamilies))

	for _, mf := range metricFamilies {
		labels := mf.GetMetric()[0].GetLabel()
		for _, label := range labels {
			val, ok := registeredLabels[mf.GetName()]
			if !ok {
				val = make(map[string]string)
			}

			val[label.GetName()] = label.GetValue()
			registeredLabels[mf.GetName()] = val
		}
	}

	assert.Equal(t, map[string]map[string]string{
		"twingate_gateway_http_requests_total": {
			"method": "get",
			"code":   "200",
		},
		"twingate_gateway_http_request_size_bytes": {
			"type":   "streaming",
			"method": "get",
			"code":   "200",
		},
		"twingate_gateway_http_response_size_bytes": {
			"type":   "streaming",
			"method": "get",
			"code":   "200",
		},
	}, registeredLabels)
}
