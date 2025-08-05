// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"k8sgateway/cmd"
	"k8sgateway/internal/token"
	"k8sgateway/internal/wsproxy"
	"k8sgateway/test/fake"
	"k8sgateway/test/integration/testutil"
)

const network = "acme"

// TestSingleUser tests the following properties:
// - User's identity is correctly forwarded to the Kubernetes API server and logged.
// - REST API request and response are audited.
// - Streaming API request and its session recording are audited.
func TestSingleUser(t *testing.T) {
	const gatewayPort = 8443

	kindKubectl, kindKubeConfig, kindBearerToken := testutil.SetupKinD(t)

	kindURL, err := url.Parse(kindKubeConfig.Host)
	require.NoError(t, err, "failed to parse API server URL")

	// Start the Controller
	controller := fake.NewController(network, 8080)
	defer controller.Close()

	t.Log("Controller is serving at", controller.URL)

	// Start the Gateway
	go func() {
		rootCmd := cmd.GetRootCommand()
		rootCmd.SetArgs([]string{
			"start",
			"--port",
			strconv.Itoa(gatewayPort),
			"--host",
			"test",
			"--network",
			network,
			"--tlsKey",
			"../data/proxy/tls.key",
			"--tlsCert",
			"../data/proxy/tls.crt",
			"--k8sAPIServerPort",
			kindURL.Port(),
			"--k8sAPIServerCA",
			"../data/api_server/tls.crt",
			"--k8sAPIServerToken",
			kindBearerToken,
			"--metricsPort",
			"0",
		})

		err := rootCmd.Execute()
		t.Logf("Failed to start Gateway: %v", err)
	}()

	testutil.GatewayHealthCheck(t, gatewayPort)

	// Set up a test logger to capture log output
	// This must be done after the proxy is started because
	// the proxy also set the global logger.
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	logger.Named("test")

	originalLogger := zap.L()
	zap.ReplaceGlobals(logger)

	defer zap.ReplaceGlobals(originalLogger) // Restore original logger

	// Create a user
	user, err := testutil.NewUser(
		&token.User{
			ID:       "user-1",
			Username: "alex@acme.com",
			Groups:   []string{"OnCall", "Engineering"},
		},
		gatewayPort,
		kindKubeConfig.Host,
		controller.URL,
	)
	require.NoError(t, err, "failed to create user")

	defer user.Close()

	testutil.CreateK8sRoleBinding(t, kindKubectl, []string{user.Username})

	// Test `kubectl auth whoami`
	output, err := user.Kubectl.Command("auth", "whoami", "-o", "json")
	require.NoError(t, err, "failed to execute kubectl auth whoami")

	testutil.AssertWhoAmI(t, output, user.Username, append(user.Groups, "system:authenticated"))

	expectedUser := map[string]any{
		"id":       "user-1",
		"username": "alex@acme.com",
		"groups":   []any{"OnCall", "Engineering"},
	}
	testutil.AssertLogsForREST(t, logs, "/apis/authentication.k8s.io/v1/selfsubjectreviews", expectedUser, http.StatusCreated)

	// Test `kubectl exec`
	output, err = user.Kubectl.Command("exec", "test-pod", "--", "cat", "/etc/hostname")
	require.NoError(t, err, "failed to execute kubectl exec")

	assert.Equal(t, "test-pod\n", string(output))

	expectedHeader := wsproxy.AsciicastHeader{
		Version:   2,
		Width:     0,
		Height:    0,
		Timestamp: 0,
		Command:   "cat /etc/hostname",
		User:      expectedUser["username"].(string),
		K8sMetadata: &wsproxy.K8sMetadata{
			PodName:   "test-pod",
			Namespace: "default",
			Container: "test-pod",
		},
	}
	expectedEvents := []string{"", "test-pod\n"}
	testutil.AssertLogsForExecOrAttach(t, logs, "/api/v1/namespaces/default/pods/test-pod/exec?command=cat&command=%2Fetc%2Fhostname&container=test-pod&stderr=true&stdout=true", expectedUser, expectedHeader, expectedEvents)

	// Test `kubectl attach`
	expectedHeader = wsproxy.AsciicastHeader{
		Version:   2,
		Width:     0,
		Height:    0,
		Timestamp: 0,
		User:      expectedUser["username"].(string),
		K8sMetadata: &wsproxy.K8sMetadata{
			PodName:   "test-pod",
			Namespace: "default",
			Container: "test-pod",
		},
	}
	expectedEvents = []string{"", "hello\n"}
	var exitError *exec.ExitError

	output, err = user.Kubectl.CommandWithTimeout(2*time.Second, "attach", "test-pod")
	require.ErrorAs(t, err, &exitError)
	require.Empty(t, exitError.Stderr, "failed to execute kubectl attach")

	assert.Contains(t, string(output), "hello\n")

	testutil.AssertLogsForExecOrAttach(t, logs, "/api/v1/namespaces/default/pods/test-pod/attach?container=test-pod&stderr=true&stdout=true", expectedUser, expectedHeader, expectedEvents)
}
