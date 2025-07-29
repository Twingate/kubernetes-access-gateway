// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"io"
	"os/exec"
	"strings"
)

type KubectlOptions struct {
	Context                  string
	ServerURL                string
	CertificateAuthorityPath string
}

// Kubectl contains context or server info to run kubectl commands.
type Kubectl struct {
	Options KubectlOptions
}

// Command is a general func to run kubectl commands.
func (k *Kubectl) Command(cmdOptions ...string) ([]byte, error) {
	return k.executeKubectl(nil, cmdOptions...)
}

// CommandWithInput is a general func to run kubectl commands with stdin input.
func (k *Kubectl) CommandWithInput(stdinInput string, cmdOptions ...string) ([]byte, error) {
	return k.executeKubectl(strings.NewReader(stdinInput), cmdOptions...)
}

func (k *Kubectl) executeKubectl(stdIn io.Reader, cmdOptions ...string) ([]byte, error) {
	var options []string
	if k.Options.Context != "" {
		options = []string{"--context", k.Options.Context}
	} else {
		options = []string{
			"--server", k.Options.ServerURL,
			"--certificate-authority", k.Options.CertificateAuthorityPath,
			"--token", "void", // Bearer token is not used but kubectl CLI requires some authentication
		}
	}

	cmd := exec.Command("kubectl", append(options, cmdOptions...)...) // #nosec G204 -- kubectl is safe to use
	cmd.Stdin = stdIn

	return RunCommand(cmd)
}
