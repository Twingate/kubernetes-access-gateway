package cmd

import (
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var rootCmd = &cobra.Command{
	Use:   "gateway",
	Short: "Twingate Kubernetes Access Gateway",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logger := zap.S()
		logger.Fatal(err)
	}
}

func GetRootCommand() *cobra.Command {
	return rootCmd
}
