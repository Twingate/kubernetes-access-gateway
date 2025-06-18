package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitMetricCollectors(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	initMetricCollectors(testRegistry)

	// Metric vectors need to have some sample data for them to be exported.
	ClientConnectionErrorsTotal.WithLabelValues("test").Inc()
	ClientAuthenticationsTotal.WithLabelValues("test").Inc()
	HTTPRequestsTotal.WithLabelValues("test", "GET", "200").Inc()
	HTTPRequestSizeBytes.WithLabelValues("test").Observe(1)
	WebsocketSessionErrorsTotal.WithLabelValues("test").Inc()

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	// Note that this list only contain a subset of Go and process metrics.
	// We want to make sure that the Go and process collectors are registered.
	expectedMetrics := []string{
		// Build Info Metric
		"twingate_gateway_build_info",
		// Go Metric
		"go_gc_duration_seconds",
		// Process Metric
		"process_cpu_seconds_total",
		// API Server Metrics
		"twingate_gateway_api_connections_active_total",
		"twingate_gateway_api_connection_duration_seconds",
		// Client Metrics
		"twingate_gateway_client_connections_active_total",
		"twingate_gateway_client_connection_duration_seconds",
		"twingate_gateway_client_connection_errors_total",
		"twingate_gateway_client_authentications_total",
		// HTTP Metrics
		"twingate_gateway_http_requests_total",
		"twingate_gateway_http_request_size_bytes",
		"twingate_gateway_http_response_size_bytes",
		// WebSocket Metrics
		"twingate_gateway_websocket_sessions_active_total",
		"twingate_gateway_websocket_session_duration_seconds",
		"twingate_gateway_websocket_session_errors_total",
	}

	registeredMetrics := make([]string, len(metricFamilies))
	for i, mf := range metricFamilies {
		registeredMetrics[i] = mf.GetName()
	}

	assert.Subset(t, registeredMetrics, expectedMetrics)
}
