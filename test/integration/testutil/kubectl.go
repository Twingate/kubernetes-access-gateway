package testutil

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type KubectlOptions struct {
	context                  string
	serverURL                string
	certificateAuthorityPath string
}

// Kubectl contains context or server info to run kubectl commands.
type Kubectl struct {
	options KubectlOptions
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
	if k.options.context != "" {
		options = []string{"--context", k.options.context}
	} else {
		options = []string{
			"--server", k.options.serverURL,
			"--certificate-authority", k.options.certificateAuthorityPath,
			"--token", "void", // Bearer token is not used but kubectl CLI requires some authentication
		}
	}

	cmd := exec.Command("kubectl", append(options, cmdOptions...)...) // #nosec G204 -- kubectl is safe to use
	cmd.Stdin = stdIn

	output, err := cmd.CombinedOutput()
	if err != nil {
		command := strings.Join(cmd.Args, " ")

		return output, fmt.Errorf("%q failed with error %q: %w", command, string(output), err)
	}

	return output, nil
}
