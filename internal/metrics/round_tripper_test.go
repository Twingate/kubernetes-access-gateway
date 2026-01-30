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

	"k8sgateway/internal/metrics/testutil"
)

func TestRoundTripper(t *testing.T) {
	t.Parallel()
	testRegistry := prometheus.NewRegistry()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	transport := RoundTripper(RoundTripperConfig{
		Registry: testRegistry,
		Next: promhttp.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
		}),
	})

	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	labelsByMetric := testutil.ExtractLabelsFromMetrics(metricFamilies)
	expectedLabels := map[string]map[string]string{
		"twingate_gateway_api_server_requests_total": {
			"type":   "http",
			"method": "get",
			"code":   "200",
		},
		"twingate_gateway_api_server_active_requests": {
			"type": "http",
		},
		"twingate_gateway_api_server_request_duration_seconds": {
			"type":   "http",
			"method": "get",
			"code":   "200",
		},
	}
	assert.Equal(t, expectedLabels, labelsByMetric)
}
