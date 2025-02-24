package cmd

import (
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var rootCmd = &cobra.Command{
	Use:   "k8sgateway",
	Short: "Twingate Kubernetes Access Gateway",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logger := zap.S()
		logger.Fatal(err)
	}
}
