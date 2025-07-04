// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Kubectl contains context to run kubectl commands.
type Kubectl struct {
	context string
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
	cmd := exec.Command("kubectl", append([]string{"--context", k.context}, cmdOptions...)...) // #nosec G204 -- kubectl is safe to use
	cmd.Stdin = stdIn

	output, err := cmd.CombinedOutput()
	if err != nil {
		command := strings.Join(cmd.Args, " ")

		return output, fmt.Errorf("%q failed with error %q: %w", command, string(output), err)
	}

	return output, nil
}
