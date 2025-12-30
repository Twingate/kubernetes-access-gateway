// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"
)

func SetupSSHServer(t *testing.T, userName string) (string, int) {
	t.Helper()

	const sshPort = 2222

	// Get user ID and group ID from the host machine and set it on the container
	// to avoid permissions issues when mounting volume
	uid, err := RunCommand(exec.Command("id", "-u"))
	require.NoError(t, err, "failed to get user ID")

	gid, err := RunCommand(exec.Command("id", "-g"))
	require.NoError(t, err, "failed to get group ID")

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err = RunCommand(exec.Command("docker", "pull", "lscr.io/linuxserver/openssh-server:latest"))
	require.NoError(t, err, "failed to pull OpenSSH server docker image")

	// #nosec G204 -- inputs are from trusted operator configuration
	output, err := RunCommand(exec.Command("docker", "run", "-d",
		"-p", fmt.Sprintf("0:%d", sshPort),
		"--name", "gateway-integration-test-ssh-server",
		"--env", "PUID="+string(uid),
		"--env", "PGID="+string(gid),
		"--env", "USER_NAME="+userName,
		"--env", "TZ=UTC",
		"--volume", "../data/ssh/sshd_test.conf:/config/sshd/sshd_config.d/sshd_test.conf",
		"lscr.io/linuxserver/openssh-server:latest",
	))
	require.NoError(t, err, "failed to create OpenSSH server docker container")

	containerID := string(output)

	// #nosec G204 -- inputs are from trusted operator configuration
	output, err = RunCommand(exec.Command("docker", "inspect", containerID,
		fmt.Sprintf("--format='{{(index (index .NetworkSettings.Ports \"%d/tcp\") 0).HostPort}}'", sshPort),
	))
	require.NoError(t, err, "failed to get docker container port mappings")

	serverPort, err := strconv.Atoi(strings.Trim(string(output), "'\n"))
	require.NoError(t, err, "failed to parse SSH server port")

	t.Cleanup(func() {
		// #nosec G204 -- output is a container ID returned by docker
		_, err = RunCommand(exec.Command("docker", "rm", "-vf", containerID))
		require.NoError(t, err, "failed to remove OpenSSH server docker container")
	})

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err = RunCommand(exec.Command("docker", "cp", "../data/ssh/ca", containerID+":/config/ca"))
	require.NoError(t, err, "failed to copy SSH CA public and private key to docker container")

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err = RunCommand(exec.Command("docker", "cp", "../data/ssh/host", containerID+":/config/host"))
	require.NoError(t, err, "failed to copy SSH host certificate and private key to docker container")

	// Private key permission must be 0600. Otherwise, it will be ignored by SSH.
	// #nosec G204 -- inputs are from trusted operator configuration
	_, err = RunCommand(exec.Command("docker", "exec", containerID, "chmod", "0600", "/config/host/host"))
	require.NoError(t, err, "failed to change permission for SSH host private key")

	err = wait.PollUntilContextTimeout(t.Context(), time.Second, 10*time.Second, true, func(_ context.Context) (bool, error) {
		// Get the sshd process ID to ensure it is already running in the docker container
		// #nosec G204 -- inputs are from trusted operator configuration
		output, err = RunCommand(exec.Command("docker", "exec", containerID, "pgrep", "sshd"))

		if err != nil || string(output) == "" {
			t.Log("Waiting for SSH server to be ready...")

			return false, nil //nolint:nilerr
		}

		t.Logf("SSH server is running at %s", fmt.Sprintf("127.0.0.1:%d", serverPort))

		return true, nil
	})
	require.NoError(t, err, "failed to start SSH server")

	return containerID, serverPort
}
