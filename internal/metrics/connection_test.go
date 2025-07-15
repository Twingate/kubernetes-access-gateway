// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockConn struct {
	net.Conn

	readErr  error
	writeErr error
	closeErr error
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}

	return len(b), nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}

	return len(b), nil
}

func (m *mockConn) Close() error {
	return m.closeErr
}

func TestSetConnectionType(t *testing.T) {
	testCases := []struct {
		name           string
		request        *http.Request
		expectedResult string
	}{
		{
			name:           "Healthcheck request",
			request:        httptest.NewRequest(http.MethodGet, healthCheckPath, nil),
			expectedResult: connectionTypeHealthcheck,
		},
		{
			name:           "POST request to healthcheck path",
			request:        httptest.NewRequest(http.MethodPost, healthCheckPath, nil),
			expectedResult: connectionTypeProxy,
		},
		{
			name:           "Proxy request",
			request:        httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil),
			expectedResult: connectionTypeProxy,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testRegistry := prometheus.NewRegistry()
			registerConnectionMetrics(testRegistry)

			conn := NewProxyConnWithMetrics(&mockConn{})
			conn.SetConnectionType(tc.request)

			assert.Equal(t, tc.expectedResult, conn.connectionType)
		})
	}
}

func TestProxyConnWithMetrics(t *testing.T) {
	testCases := []struct {
		name           string
		conn           *mockConn
		runConn        func(*ProxyConnWithMetrics) (int, error)
		expectError    bool
		expectedLabels map[string]map[string]string
	}{
		{
			name: "No errors",
			conn: &mockConn{},
			runConn: func(conn *ProxyConnWithMetrics) (int, error) {
				b := make([]byte, 0)
				_, err := conn.Read(b)
				if err != nil {
					return 0, err
				}

				_, err = conn.Write(b)
				if err != nil {
					return 0, err
				}

				err = conn.Close()
				if err != nil {
					return 0, err
				}

				return 0, nil
			},
			expectError: false,
			expectedLabels: map[string]map[string]string{
				"twingate_gateway_active_client_connections": {},
				"twingate_gateway_client_connection_duration_seconds": {
					"conn_type": connectionTypeProxy,
				},
			},
		},
		{
			name: "Read error should skip io.EOF",
			conn: &mockConn{readErr: io.EOF},
			runConn: func(conn *ProxyConnWithMetrics) (int, error) {
				defer conn.Close()

				return conn.Read(make([]byte, 0))
			},
			expectError: true,
			expectedLabels: map[string]map[string]string{
				"twingate_gateway_active_client_connections": {},
				"twingate_gateway_client_connection_duration_seconds": {
					"conn_type": connectionTypeProxy,
				},
			},
		},
		{
			name: "Write error",
			conn: &mockConn{writeErr: assert.AnError},
			runConn: func(conn *ProxyConnWithMetrics) (int, error) {
				defer conn.Close()

				return conn.Write(make([]byte, 0))
			},
			expectError: true,
			expectedLabels: map[string]map[string]string{
				"twingate_gateway_active_client_connections": {},
				"twingate_gateway_client_connection_duration_seconds": {
					"conn_type": connectionTypeProxy,
				},
				"twingate_gateway_client_connection_errors_total": {
					"conn_type": connectionTypeProxy,
					"type":      errorTypeWrite,
				},
			},
		},
		{
			name: "Read error",
			conn: &mockConn{readErr: assert.AnError},
			runConn: func(conn *ProxyConnWithMetrics) (int, error) {
				defer conn.Close()

				return conn.Read(make([]byte, 0))
			},
			expectError: true,
			expectedLabels: map[string]map[string]string{
				"twingate_gateway_active_client_connections": {},
				"twingate_gateway_client_connection_duration_seconds": {
					"conn_type": connectionTypeProxy,
				},
				"twingate_gateway_client_connection_errors_total": {
					"conn_type": connectionTypeProxy,
					"type":      errorTypeRead,
				},
			},
		},
		{
			name: "Close error",
			conn: &mockConn{closeErr: assert.AnError},
			runConn: func(conn *ProxyConnWithMetrics) (int, error) {
				return 0, conn.Close()
			},
			expectError: true,
			expectedLabels: map[string]map[string]string{
				"twingate_gateway_active_client_connections": {},
				"twingate_gateway_client_connection_duration_seconds": {
					"conn_type": connectionTypeProxy,
				},
				"twingate_gateway_client_connection_errors_total": {
					"conn_type": connectionTypeProxy,
					"type":      errorTypeClose,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testRegistry := prometheus.NewRegistry()
			registerConnectionMetrics(testRegistry)

			conn := NewProxyConnWithMetrics(tc.conn)
			conn.SetConnectionType(&http.Request{})

			_, err := tc.runConn(conn)

			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			metricFamilies, err := testRegistry.Gather()
			require.NoError(t, err)

			labelsByMetrics := extractLabelsFromMetrics(metricFamilies)
			assert.Equal(t, tc.expectedLabels, labelsByMetrics)
		})
	}
}
