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
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))
	defer server.Close()

	getReq, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err, "Failed to create request")

	// Make a dummy GET request to trigger the middleware
	getResp, err := http.DefaultClient.Do(getReq)
	require.NoError(t, err, "Failed to send request")
	defer getResp.Body.Close()

	expectedMetrics := []string{
		"twingate_gateway_http_requests_total",
		"twingate_gateway_http_request_size_bytes",
		"twingate_gateway_http_response_size_bytes",
	}

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	registeredMetrics := make([]string, len(metricFamilies))
	for i, mf := range metricFamilies {
		registeredMetrics[i] = mf.GetName()
	}

	assert.Subset(t, registeredMetrics, expectedMetrics)
}
