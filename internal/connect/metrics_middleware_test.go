// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"k8sgateway/internal/metrics/testutil"
)

type mockValidator struct {
	mock.Mock
}

func (v *mockValidator) ParseConnect(req *http.Request, ekm []byte) (Info, error) {
	args := v.Called(req, ekm)

	return args[0].(Info), args.Error(1)
}

func TestInstrumentHTTPConnect(t *testing.T) {
	tests := []struct {
		name           string
		setupValidator func(*mockValidator)
		expectedCode   string
	}{
		{
			name: "Successful authentication",
			setupValidator: func(v *mockValidator) {
				v.On("ParseConnect", mock.Anything, mock.Anything).Return(Info{}, nil)
			},
			expectedCode: "200",
		},
		{
			name: "Authentication failed with HTTPError",
			setupValidator: func(v *mockValidator) {
				v.On("ParseConnect", mock.Anything, mock.Anything).Return(Info{}, &HTTPError{Code: http.StatusUnauthorized, Message: "unauthorized", Err: errors.New("auth failed")})
			},
			expectedCode: "401",
		},
		{
			name: "Authentication failed with bad request",
			setupValidator: func(v *mockValidator) {
				v.On("ParseConnect", mock.Anything, mock.Anything).Return(Info{}, errors.New("bad request"))
			},
			expectedCode: "400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			RegisterHTTPConnectMetrics(registry)

			mockValidator := &mockValidator{}
			tt.setupValidator(mockValidator)

			parseConnect := InstrumentHTTPConnect(mockValidator)

			req := httptest.NewRequest(http.MethodConnect, "https://example.com", nil)
			ekm := []byte("test-signature")

			_, err := parseConnect(req, ekm)
			if tt.expectedCode != "200" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockValidator.AssertExpectations(t)

			metricFamilies, err := registry.Gather()
			require.NoError(t, err)

			labelsByMetric := testutil.ExtractLabelsFromMetrics(metricFamilies)
			expectedLabels := map[string]map[string]string{
				"twingate_gateway_tcp_connection_authentication_total": {
					"code": tt.expectedCode,
				},
				"twingate_gateway_tcp_connection_authentication_duration_seconds": {
					"code": tt.expectedCode,
				},
			}

			assert.Equal(t, expectedLabels, labelsByMetric)
		})
	}
}
