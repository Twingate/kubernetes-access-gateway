package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"k8sgateway/internal/log"
)

func TestRootCmd_StartCommandArgs(t *testing.T) {
	log.InitializeLogger("gateway", false)

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
		"--network", "acme",
		"--tlsKey", "test-tls-key",
		"--tlsCert", "test-tls-cert",
		"--k8sAPIServerToken", "test-token",
		"--k8sAPIServerCA", "test-ca",
		"--debug",
	})

	err := cmd.Execute()
	if assert.NoError(t, err) {
		assert.True(t, startMockCalled)

		assert.Equal(t, "acme", viper.GetString("network"))
		assert.Equal(t, "test-tls-key", viper.GetString("tlsKey"))
		assert.Equal(t, "test-tls-cert", viper.GetString("tlsCert"))
		assert.Equal(t, "test-token", viper.GetString("k8sAPIServerToken"))
		assert.Equal(t, "test-ca", viper.GetString("k8sAPIServerCA"))
		assert.True(t, viper.GetBool("debug"))
	}
}
