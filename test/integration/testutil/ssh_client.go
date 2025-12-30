// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"

	"k8sgateway/internal/sshhandler"
)

var sshBanner = []byte(sshhandler.Banner)

var errMissingBanner = errors.New("output does not start with SSH banner")

type SSH struct {
	username       string
	hostname       string
	port           string
	knownHostsFile string
}

// Command is a general func to run ssh commands.
func (s *SSH) Command(cmdOptions ...string) ([]byte, error) {
	return s.executeSSH(context.Background(), cmdOptions...)
}

// CopyFileToHost is a func to copy files from SSH server to host using scp command.
func (s *SSH) CopyFileToHost(remoteDest, localDest string, cmdOptions ...string) ([]byte, error) {
	source := fmt.Sprintf("%s@%s:%s", s.username, s.hostname, remoteDest)

	return s.copy(context.Background(), source, localDest, cmdOptions...)
}

func (s *SSH) executeSSH(ctx context.Context, cmdOptions ...string) ([]byte, error) {
	var options = []string{
		s.hostname,
		"-l", s.username,
		"-p", s.port,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + s.knownHostsFile,
	}

	// #nosec G204 -- ssh is safe to use
	cmd := exec.CommandContext(ctx, "ssh", append(options, cmdOptions...)...)

	return runCommandAndStripBanner(cmd)
}

func (s *SSH) copy(ctx context.Context, source, target string, cmdOptions ...string) ([]byte, error) {
	var options = []string{
		"-P", s.port,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + s.knownHostsFile,
	}

	options = append(options, cmdOptions...)

	// #nosec G204 -- scp is safe to use
	cmd := exec.CommandContext(ctx, "scp", append(options, source, target)...)

	return runCommandAndStripBanner(cmd)
}

func runCommandAndStripBanner(cmd *exec.Cmd) ([]byte, error) {
	output, err := RunCommand(cmd)
	if err != nil {
		return nil, err
	}

	strippedOutput, err := stripSSHBanner(output)
	if err != nil {
		return nil, err
	}

	return strippedOutput, nil
}

func stripSSHBanner(output []byte) ([]byte, error) {
	if !bytes.HasPrefix(output, sshBanner) {
		return nil, errMissingBanner
	}

	return bytes.TrimPrefix(output, sshBanner), nil
}
