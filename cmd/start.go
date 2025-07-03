// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"k8s.io/client-go/rest"

	"k8sgateway/internal/connect"
	"k8sgateway/internal/httpproxy"
	"k8sgateway/internal/log"
	"k8sgateway/internal/metrics"
	"k8sgateway/internal/token"
)

var errRequiredConfig = errors.New("required configuration must be set")

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start Twingate Kubernetes Access Gateway",
	RunE: func(_cmd *cobra.Command, _args []string) error {
		newProxy := func(cfg httpproxy.Config) (httpproxy.ProxyService, error) {
			return httpproxy.NewProxy(cfg)
		}

		return start(newProxy)
	},
}

type ProxyFactory func(httpproxy.Config) (httpproxy.ProxyService, error)

func start(newProxy ProxyFactory) error {
	log.InitializeLogger("gateway", viper.GetBool("debug"))

	logger := zap.S()
	logger.Infof("Gateway start called: %+v", viper.AllSettings())

	network := viper.GetString("network")

	if network == "" {
		return fmt.Errorf("%w: network", errRequiredConfig)
	}

	parser, err := token.NewParser(token.ParserConfig{
		Network: network,
		Host:    viper.GetString("host"),
		URL:     viper.GetString("fakeControllerURL"),
	})
	if err != nil {
		return fmt.Errorf("failed to create token parser %w", err)
	}

	cfg := httpproxy.Config{
		Port:              viper.GetInt("port"),
		TLSKey:            viper.GetString("tlsKey"),
		TLSCert:           viper.GetString("tlsCert"),
		K8sAPIServerCA:    viper.GetString("k8sAPIServerCA"),
		K8sAPIServerToken: viper.GetString("k8sAPIServerToken"),
		K8sAPIServerPort:  viper.GetInt("k8sAPIServerPort"),
		ConnectValidator: &connect.MessageValidator{
			TokenParser: parser,
		},
		LogFlushSizeThreshold: viper.GetInt("logFlushSizeThreshold"),
		LogFlushInterval:      viper.GetDuration("logFlushInterval"),
	}

	if inClusterK8sCfg, err := rest.InClusterConfig(); inClusterK8sCfg != nil {
		logger.Info("Using in-cluster configuration")

		cfg.K8sAPIServerCA = inClusterK8sCfg.CAFile
		cfg.K8sAPIServerToken = inClusterK8sCfg.BearerToken
		cfg.K8sAPIServerTokenFile = inClusterK8sCfg.BearerTokenFile
		cfg.TLSCert = "/etc/tls-secret-volume/tls.crt"
		cfg.TLSKey = "/etc/tls-secret-volume/tls.key"
	} else if !errors.Is(err, rest.ErrNotInCluster) {
		logger.Errorf("failed to load in-cluster config: %v", err)
	}

	metricsPort := viper.GetInt("metricsPort")
	go func() {
		logger.Infof("Starting metrics server on: %v", metricsPort)

		err := metrics.Start(metrics.Config{
			Port: metricsPort,
		})
		if err != nil {
			logger.Fatal("failed to start metrics server:", zap.Error(err))
		}
	}()

	proxy, err := newProxy(cfg)
	if err != nil {
		return fmt.Errorf("failed to create k8s gateway %w", err)
	}

	proxy.Start(nil)

	return nil
}

func init() { //nolint:gochecknoinits
	viper.SetEnvPrefix("TWINGATE")
	viper.AutomaticEnv()

	flags := startCmd.Flags()

	// Twingate flags
	flags.String("network", "", "Twingate network ID. For example, network ID is autoco if your URL is autoco.twingate.com")
	flags.String("host", "twingate.com", "The Twingate service domain")

	// Gateway flags
	flags.String("port", "8443", "Port to listen on")
	flags.String("tlsCert", "", "Path to the TLS certificate for the Gateway")
	flags.String("tlsKey", "", "Path to the TLS key for the Gateway")
	flags.Int("logFlushSizeThreshold", 1_000_000, "Threshold (in bytes) of the recorded lines to flush")
	flags.Duration("logFlushInterval", 10*time.Minute, "Interval to flush logs e.g. 30s, 1m, 1h")

	// Kubernetes flags
	flags.String("k8sAPIServerCA", "", "Path to the CA certificate for the Kubernetes API server")
	flags.String("k8sAPIServerToken", "", "Bearer token to authenticate to the Kubernetes API server")
	flags.Int("k8sAPIServerPort", 0, "K8s API Server port, used in local development and testing to override 443 port")

	// Metrics flags
	flags.Int("metricsPort", 9090, "Port to expose Prometheus metrics on")

	// Misc flags
	flags.BoolP("debug", "d", false, "Run in debug mode")
	flags.String("fakeControllerURL", "", "URL of fake Controller which issues and verifies GAT. Used for testing")

	if err := viper.BindPFlags(flags); err != nil {
		panic(fmt.Sprintf("failed to bind flags: %v", err))
	}

	rootCmd.AddCommand(startCmd)
}
