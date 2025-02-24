package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"k8sgateway/internal/log"
)

func TestRootCmd_StartCommandArgs(t *testing.T) {
	log.InitializeLogger("k8sgatewaytest", false)

	startMockCalled := false
	startCmd.RunE = func(_cmd *cobra.Command, _args []string) error {
		startMockCalled = true

		return nil
	}

	cmd := rootCmd
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	cmd.SetArgs([]string{
		"start",
		"--k8sAPIToken", "test-token",
		"--ca", "test-ca",
		"--tls.key", "test-tls-key",
		"--tls.cert", "test-tls-cert",
		"--debug",
	})

	err := cmd.Execute()
	if assert.NoError(t, err) {
		assert.True(t, startMockCalled)

		assert.Equal(t, "test-token", startFlags.K8sAPIServerToken)
		assert.Equal(t, "test-ca", startFlags.CA)
		assert.Equal(t, "test-tls-key", startFlags.TLSKey)
		assert.Equal(t, "test-tls-cert", startFlags.TLSCert)
		assert.True(t, startFlags.Debug)
	}
}
