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
	Stdin   io.Reader
}

// Command is a general func to run kubectl commands.
func (k *Kubectl) Command(cmdOptions ...string) ([]byte, error) {
	cmd := exec.Command("kubectl", append([]string{"--context", k.context}, cmdOptions...)...) // #nosec G204 -- kubectl is safe to use
	cmd.Stdin = k.Stdin

	output, err := cmd.CombinedOutput()
	if err != nil {
		command := strings.Join(cmd.Args, " ")

		return output, fmt.Errorf("%q failed with error %q: %w", command, string(output), err)
	}

	return output, nil
}

// WithInput is a general func to run kubectl commands with input.
func (k *Kubectl) WithInput(stdinInput string) *Kubectl {
	k.Stdin = strings.NewReader(stdinInput)

	return k
}
