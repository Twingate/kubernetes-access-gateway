// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func GatewayHealthCheck(t *testing.T, port int) {
	t.Helper()
	t.Log("Waiting for Gateway to be ready...")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // #nosec G402: Skip certificate verification for the health check
			},
		},
		Timeout: 200 * time.Millisecond,
	}

	// Try to connect to the health endpoint with fixed backoff
	backoff := 100 * time.Millisecond
	maxAttempts := 5
	gatewayURL := fmt.Sprintf("https://127.0.0.1:%d/healthz", port)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := client.Get(gatewayURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			err := resp.Body.Close()
			require.NoError(t, err)

			t.Log("Gateway is ready at", gatewayURL)

			break
		}

		if resp != nil {
			err := resp.Body.Close()
			require.NoError(t, err)
		}

		if attempt == maxAttempts {
			t.Fatalf("Gateway failed to start after %d attempts", maxAttempts)
		}

		time.Sleep(backoff)
	}
}
