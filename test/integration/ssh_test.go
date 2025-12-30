// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	gatewayconfig "k8sgateway/internal/config"
	"k8sgateway/internal/proxy"
	"k8sgateway/internal/token"
	"k8sgateway/test/data"
	"k8sgateway/test/fake"
	"k8sgateway/test/integration/testutil"
)

const (
	sshUsername = "admin"
	gatewayPort = 8445
)

// TestSSH tests the following properties:
// - User can execute commands via SSH through the gateway
// - Session recording (asciicast) is properly generated
// - User can copy file from remote server to host.
func TestSSH(t *testing.T) {
	containerID, sshServerPort := testutil.SetupSSHServer(t, sshUsername)
	sshServerAddress := fmt.Sprintf("127.0.0.1:%d", sshServerPort)

	controller := fake.NewController(network, 8080)
	defer controller.Close()

	t.Log("Controller is serving at", controller.URL)

	config := gatewayconfig.Config{
		Twingate: gatewayconfig.TwingateConfig{
			Network: network,
			Host:    host,
		},
		Port:        gatewayPort,
		MetricsPort: 0,
		TLS: gatewayconfig.TLSConfig{
			CertificateFile: "../data/proxy/tls.crt",
			PrivateKeyFile:  "../data/proxy/tls.key",
		},
		SSH: &gatewayconfig.SSHConfig{
			Gateway: gatewayconfig.SSHGatewayConfig{
				Username: sshUsername,
			},
			CA: gatewayconfig.SSHCAConfig{
				Manual: &gatewayconfig.SSHCAManualConfig{
					PrivateKeyFile: "../data/ssh/ca/ca",
				},
			},
			Upstreams: []gatewayconfig.SSHUpstream{
				{Name: "ssh-server", Address: sshServerAddress},
			},
		},
	}

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core).Named("test")

	p, err := proxy.NewProxy(&config, prometheus.NewRegistry(), logger)
	require.NoError(t, err, "failed to create proxy")

	// Start the Gateway
	go func() {
		err := p.Start()
		t.Logf("Failed to start Gateway: %v", err)
	}()

	testutil.GatewayHealthCheck(t, gatewayPort)

	knownHostsFile := filepath.Join(t.TempDir(), "known_hosts")
	line := "@cert-authority * " + string(data.SSHCAPublicKey)
	require.NoError(t, os.WriteFile(knownHostsFile, []byte(line), 0600), "failed to create SSH known_hosts file")

	// Create a user with SSH client
	user, err := testutil.NewSSHUser(
		&token.User{
			ID:       "user-ssh-1",
			Username: "alex@acme.com",
			Groups:   []string{"OnCall", "Engineering"},
		},
		gatewayPort,
		sshServerAddress,
		controller.URL,
		knownHostsFile,
	)
	require.NoError(t, err, "failed to create SSH user")

	require.NotNil(t, user.SSH, "failed to create SSH client")
	defer user.Close()

	// Test `ssh 127.0.0.1 -l admin -p 2222 "whoami"`
	output, err := user.SSH.Command("whoami")
	require.NoError(t, err, "failed to execute 'whoami' command")

	assert.Equalf(t, sshUsername+"\n", string(output), "whoami should return '%s'", sshUsername)

	// Wait for logs to be flushed
	time.Sleep(100 * time.Millisecond)

	expectedRequest := map[string]any{
		"type":    "exec",
		"command": "whoami",
	}
	expectedUser := map[string]any{
		"id":       "user-ssh-1",
		"username": "alex@acme.com",
		"groups":   []any{"OnCall", "Engineering"},
	}
	testutil.AssertLogsForSSH(t, logs, expectedUser, expectedRequest)

	// Clear existing logs
	logs.TakeAll()

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err = testutil.RunCommand(exec.Command("docker", "exec", containerID, "sh", "-c", "echo 'test file copy' > /tmp/test.txt"))
	require.NoError(t, err, "failed to create test file in docker container")

	// Test `scp -P 2222 admin@127.0.0.1:/tmp/test.txt /tmp/dir/test.txt`
	tmpFile := filepath.Join(t.TempDir(), "test.txt")
	_, err = user.SSH.CopyFileToHost("/tmp/test.txt", tmpFile)
	require.NoError(t, err, "failed to copy '/tmp/test.txt' file locally")

	// #nosec G304 -- file paths are from trusted operator configuration
	fileContent, err := os.ReadFile(tmpFile)
	require.NoErrorf(t, err, "failed to read file %s", tmpFile)

	assert.Equal(t, "test file copy\n", string(fileContent))

	// Wait for logs to be flushed
	time.Sleep(100 * time.Millisecond)

	expectedRequest = map[string]any{
		"type": "subsystem",
		"name": "sftp",
	}
	testutil.AssertLogsForSSH(t, logs, expectedUser, expectedRequest)
}
