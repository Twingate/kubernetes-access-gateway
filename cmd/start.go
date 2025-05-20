package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"k8s.io/client-go/rest"

	"k8sgateway/internal/connect"
	"k8sgateway/internal/httpproxy"
	"k8sgateway/internal/log"
	"k8sgateway/internal/token"
)

type StartFlags = struct {
	CA                string
	TLSKey            string
	TLSCert           string
	K8sAPIServerToken string
	Network           string
	Host              string
	Debug             bool
}

var startFlags = StartFlags{}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start Twingate Kubernetes Access Gateway",
	RunE: func(_cmd *cobra.Command, _args []string) error {
		startFlags.Network = viper.GetString("network")
		startFlags.Host = viper.GetString("host")

		newProxy := func(cfg httpproxy.Config) (httpproxy.ProxyService, error) {
			return httpproxy.NewProxy(cfg)
		}

		return start(newProxy)
	},
}

type ProxyFactory func(httpproxy.Config) (httpproxy.ProxyService, error)

func start(newProxy ProxyFactory) error {
	f := startFlags
	log.InitializeLogger("k8sgateway", f.Debug)

	logger := zap.S()
	logger.Infof("Gateway start called with: %+v", startFlags)

	parser, err := token.NewParserWithRemotesJWKS(f.Network, f.Host)
	if err != nil {
		return fmt.Errorf("failed to create token parser %w", err)
	}

	connectValidator := &connect.MessageValidator{
		TokenParser: parser,
	}

	if inClusterK8sCfg, _ := rest.InClusterConfig(); inClusterK8sCfg != nil {
		logger.Infof("Using in-cluster configuration")

		f.CA = inClusterK8sCfg.CAFile
		f.K8sAPIServerToken = inClusterK8sCfg.BearerToken
		f.TLSCert = "/etc/tls-secret-volume/tls.crt"
		f.TLSKey = "/etc/tls-secret-volume/tls.key"
	} else if !errors.Is(err, rest.ErrNotInCluster) {
		logger.Errorf("failed to load in-cluster config: %v", err)
	}

	proxy, err := newProxy(httpproxy.Config{
		CA:                f.CA,
		TLSKey:            f.TLSKey,
		TLSCert:           f.TLSCert,
		K8sAPIServerToken: f.K8sAPIServerToken,
		ConnectValidator:  connectValidator,
	})
	if err != nil {
		return fmt.Errorf("failed to create k8s gateway %w", err)
	}

	proxy.Start(nil)

	return nil
}

func init() {
	viper.SetEnvPrefix("TWINGATE")
	viper.AutomaticEnv()
	flags := startCmd.Flags()
	flags.StringVar(&startFlags.CA, "ca", "../../test/data/ca.crt", "Root CA certificate")
	flags.StringVar(&startFlags.TLSKey, "tls.key", "../../test/data/domain.key", "TLS key")
	flags.StringVar(&startFlags.TLSCert, "tls.cert", "../../test/data/domain.crt", "TLS certificate")
	flags.StringVar(&startFlags.K8sAPIServerToken, "k8sAPIToken", "", "k8s API Server Token")
	flags.StringVar(&startFlags.Network, "network", "", "Twingate network ID. For example, network ID is autoco if your URL is autoco.twingate.com")
	flags.StringVar(&startFlags.Host, "host", "twingate.com", "The Twingate service domain")
	flags.BoolVarP(&startFlags.Debug, "debug", "d", viper.GetBool("DEBUG"), "Run in debug mode")

	if err := viper.BindPFlag("network", flags.Lookup("network")); err != nil {
		panic(fmt.Sprintf("failed to initialize: %v", err))
	}
	if err := viper.BindPFlag("host", flags.Lookup("host")); err != nil {
		panic(fmt.Sprintf("failed to initialize: %v", err))
	}

	rootCmd.AddCommand(startCmd)
}
