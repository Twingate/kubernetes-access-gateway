// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	kindcluster "sigs.k8s.io/kind/pkg/cluster"
	kindcmd "sigs.k8s.io/kind/pkg/cmd"

	"k8sgateway/internal/token"
	"k8sgateway/test/fake"
	"k8sgateway/test/integration/testutil"
)

const (
	network               = "acme"
	gatewayPort           = 8443
	gatewayHost           = "127.0.0.1"
	kubeConfigPath        = "config-twingate-gateway-local"
	clusterName           = "gateway-local-development"
	kindClusterName       = "kind-" + clusterName
	kindPort              = 6443
	controllerPort        = 8080
	kubeConfigClusterName = "twingate-gateway-local"
	defaultUsername       = "alex@acme.com"
)

var kindClusterYaml = fmt.Sprintf(`
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerPort: %d
nodes:
- role: control-plane
  extraMounts:
    - hostPath: ./test/data/api_server/tls.crt
      containerPath: /etc/kubernetes/pki/ca.crt
    - hostPath: ./test/data/api_server/tls.key
      containerPath: /etc/kubernetes/pki/ca.key
`, kindPort)

// Before running this local dev client, you need to do the following:
// - Caddy must be already running. Run `caddy run` to start Caddy.
// - Update `kubeConfigPath` above to point to your local KubeConfig file.
func main() {
	// Parse command line flags
	username := flag.String("username", defaultUsername, "Username to use for authentication")
	createKubeConfig := flag.Bool("create-kubeconfig", true, "Whether to create kubeConfig. If kubeConfig already exists, it will be overwritten")
	flag.Parse()

	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}

	defer func() {
		_ = logger.Sync()
	}()

	zap.ReplaceGlobals(logger)

	// Create a context that's canceled when SIGINT or SIGTERM is received
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		logger.Info("Received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	if err := createKindCluster(logger, *username); err != nil {
		logger.Fatal("Failed to create kind cluster", zap.Error(err))
	}

	controller := fake.NewController(network, controllerPort)
	defer controller.Close()

	logger.Info("Controller is serving at", zap.String("url", controller.URL))

	user := &token.User{
		ID:       "user-1",
		Username: *username,
		Groups:   []string{"Developer", "OnCall"},
	}

	client := fake.NewClient(
		user,
		fmt.Sprintf("%s:%d", gatewayHost, gatewayPort),
		controller.URL,
		"https://127.0.0.1:6443",
	)
	defer client.Close()

	logger.Info("Client is serving at", zap.String("url", client.URL))

	if *createKubeConfig {
		if err := createKubeConfigFile(client.URL); err != nil {
			logger.Error("Failed to create kubeConfig", zap.Error(err))

			return
		}

		logger.Info("Created kubeConfig", zap.String("path", kubeConfigPath))
	}

	kindBearerToken, err := getKinDBearerToken()
	if err != nil {
		logger.Error("Failed to get bearer token", zap.Error(err))

		return
	}

	//nolint:forbidigo
	_, _ = fmt.Printf(`
=====================================================
Twingate local dev environment running!
Controller: %s
Client:     %s
User:       %s
KubeConfig:  %s (context: %s)
Start the Gateway at the project root with this command:
go run main.go start --network %s --host test --debug --tlsKey ./test/data/proxy/tls.key --tlsCert ./test/data/proxy/tls.crt --k8sAPIServerPort %d --k8sAPIServerCA ./test/data/api_server/tls.crt --k8sAPIServerToken %s

Press Ctrl+C to stop
=====================================================
	`, controller.URL, client.URL, user.Username, kubeConfigPath, kindClusterName, network, kindPort, kindBearerToken)

	// Wait for context cancellation
	<-ctx.Done()
}

const setupYaml = `
# Setup default service account for impersonation
#
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: gateway-impersonation
rules:
- apiGroups:
  - ""
  resources:
  - users
  - groups
  - serviceaccounts
  verbs:
  - impersonate
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: gateway-impersonation
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: gateway-impersonation
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
---
apiVersion: v1
kind: Secret
metadata:
  name: gateway-default-service-account
  annotations:
    kubernetes.io/service-account.name: default
type: kubernetes.io/service-account-token
---

# Setup a test pod
#
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: test-pod
    image: busybox
    command: ["sleep", "3600"]
---

# Setup role binding for test user
#
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: gateway-test-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: edit
subjects:
- kind: User
  name: %s
  apiGroup: rbac.authorization.k8s.io
`

func createKindCluster(logger *zap.Logger, username string) error {
	provider := kindcluster.NewProvider(kindcluster.ProviderWithLogger(kindcmd.NewLogger()))

	existingClusters, err := provider.List()
	if err != nil {
		return err
	}

	for _, cluster := range existingClusters {
		if cluster == clusterName {
			logger.Info("Cluster already exists", zap.String("cluster", clusterName))

			return nil
		}
	}

	logger.Info("Creating cluster", zap.String("cluster", clusterName))

	if err := provider.Create(clusterName, kindcluster.CreateWithRawConfig([]byte(kindClusterYaml))); err != nil {
		return err
	}

	kubectl := &testutil.Kubectl{
		Options: testutil.KubectlOptions{
			Context: kindClusterName,
		},
	}

	// It takes a while for KinD to create the `default` service account...
	logger.Info("Waiting for default service account to be created...")

	err = wait.PollUntilContextTimeout(context.Background(), time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err = kubectl.CommandContext(ctx, "get", "serviceaccount", "default")
		if err != nil {
			return false, nil //nolint:nilerr
		}

		return true, nil
	})
	if err != nil {
		logger.Fatal("Failed waiting for default service account", zap.Error(err))
	}

	_, err = kubectl.CommandWithInput(fmt.Sprintf(setupYaml, username), "apply", "-f", "-")
	if err != nil {
		logger.Fatal("Failed to apply setup YAML", zap.Error(err))
	}

	_, err = kubectl.Command("wait", "--for=condition=Ready", "pod/test-pod", "--timeout=30s")
	if err != nil {
		logger.Fatal("Failed waiting for busybox pod", zap.Error(err))
	}

	return nil
}

func getKinDBearerToken() (string, error) {
	kubectl := &testutil.Kubectl{
		Options: testutil.KubectlOptions{
			Context: kindClusterName,
		},
	}

	b64BearerToken, err := kubectl.Command("get", "secret", "gateway-default-service-account", "-o", "jsonpath={.data.token}")
	if err != nil {
		return "", err
	}

	bearerToken, err := base64.StdEncoding.DecodeString(string(b64BearerToken))
	if err != nil {
		return "", err
	}

	return string(bearerToken), nil
}

// createKubeConfigFile creates the KubeConfig file for the local dev environment.
// If kubeConfig file already exists, it will be overwritten.
func createKubeConfigFile(serverURL string) error {
	config := api.NewConfig()

	cluster := api.NewCluster()
	cluster.Server = serverURL
	cluster.InsecureSkipTLSVerify = true
	config.Clusters[kubeConfigClusterName] = cluster

	// Create auth info (no credentials needed as the fake client handles auth)
	authInfo := &api.AuthInfo{
		Token: "void",
	}
	config.AuthInfos[kubeConfigClusterName] = authInfo

	ctx := api.NewContext()
	ctx.Cluster = kubeConfigClusterName
	ctx.AuthInfo = kubeConfigClusterName
	config.Contexts[kubeConfigClusterName] = ctx

	config.CurrentContext = kubeConfigClusterName

	return clientcmd.WriteToFile(*config, kubeConfigPath)
}
