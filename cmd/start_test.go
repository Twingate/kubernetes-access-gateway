package cmd

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8sgateway/internal/httpproxy"
)

type mockProxy struct {
	startCalled bool
}

func (m *mockProxy) Start(_ready chan struct{}) {
	m.startCalled = true
}

func TestStart(t *testing.T) {
	tests := []struct {
		name           string
		setFlags       func()
		newProxyErr    error
		wantErr        bool
		wantErrMessage string
	}{
		{
			name: "successful start",
			setFlags: func() {
				startFlags = StartFlags{
					CA:                "test-ca",
					TLSKey:            "test-key",
					TLSCert:           "test-cert",
					K8sAPIServerToken: "test-token",
					Network:           "test-network",
					Host:              "test-host.com",
					Debug:             false,
				}
			},
			newProxyErr: nil,
			wantErr:     false,
		},
		{
			name: "gateway creation fails",
			setFlags: func() {
				startFlags = StartFlags{
					CA:                "invalid-ca",
					TLSKey:            "invalid-key",
					TLSCert:           "invalid-cert",
					K8sAPIServerToken: "invalid-token",
					Network:           "invalid-network",
					Host:              "invalid-host",
					Debug:             true,
				}
			},
			newProxyErr:    errors.New("invalid configuration"),
			wantErr:        true,
			wantErrMessage: "failed to create k8s gateway invalid configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setFlags()

			var mockProxyInstance *mockProxy

			mockNewProxy := func(_config httpproxy.Config) (httpproxy.ProxyService, error) {
				mockProxyInstance = &mockProxy{}

				return mockProxyInstance, tt.newProxyErr
			}

			err := start(mockNewProxy)

			if tt.wantErr {
				require.Error(t, err)

				if tt.wantErrMessage != "" {
					assert.Equal(t, tt.wantErrMessage, err.Error())
				}
			} else {
				require.NoError(t, err)
				assert.True(t, mockProxyInstance.startCalled)
			}
		})
	}
}
