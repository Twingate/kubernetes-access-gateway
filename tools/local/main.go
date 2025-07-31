package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/kind/pkg/cluster"

	kindcmd "sigs.k8s.io/kind/pkg/cmd"

	"k8sgateway/internal/token"
	"k8sgateway/test/fake"
)

const (
	network         = "acme"
	host            = "twingate.local"
	gatewayPort     = 8443
	gatewayHost     = "127.0.0.1"
	kubeconfigPath  = "/Users/minhtule/.kube/config-twingate-gateway-local"
	kindClusterName = "gateway-local-development"
	kindPort        = 6443
	controllerPort  = 8080
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

func main() {
	// Parse command line flags
	// username := flag.String("username", defaultUsername, "Username to use for authentication")
	// k8sAPIServerHost := flag.String("k8s-api-server", kubeServerHost, "Kubernetes API server URL")
	// updateKubeconfig := flag.Bool("update-kubeconfig", true, "Whether to update kubeconfig")
	// flag.Parse()
	// Set up logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}

	defer logger.Sync()
	zap.ReplaceGlobals(logger)

	// Create a context that's canceled when SIGINT or SIGTERM is received
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		logger.Info("Received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	// Check if there is a kind cluster, if not create one
	if err := createKindCluster(logger); err != nil {
		logger.Fatal("Failed to create kind cluster", zap.Error(err))
	}

	// Start the controller
	controller := fake.NewController(network, controllerPort)
	defer controller.Close()
	logger.Info("Controller is serving at", zap.String("url", controller.URL))

	// Setup user for the fake client
	user := &token.User{
		ID:       "user-1",
		Username: "alex@acme.com",
		Groups:   []string{"Developer", "OnCall"},
	}

	// Start the fake client
	client := fake.NewClient(
		user,
		fmt.Sprintf("%s:%d", gatewayHost, gatewayPort),
		controller.URL,
		"https://127.0.0.1:8443",
	)
	defer client.Close()

	logger.Info("Client is serving at", zap.String("url", client.URL))

	// Update kubeconfig if requested
	if err := updateKubeconfigFile(client.URL); err != nil {
		logger.Error("Failed to update kubeconfig", zap.Error(err))

		return
	} else {
		logger.Info("Updated kubeconfig", zap.String("path", kubeconfigPath))
		logger.Info("You can now use kubectl with this config:",
			zap.String("command", fmt.Sprintf("kubectl --kubeconfig=%s get pods", "twingate-gateway-local")))
	}

	// Get bearer token
	kindBearerToken, err := getKinDBearerToken()
	if err != nil {
		logger.Error("Failed to get bearer token", zap.Error(err))

		return
	}

	// Print success message
	fmt.Printf("\n=====================================================\n")
	fmt.Printf("Twingate dev environment running!\n")
	fmt.Printf("Controller: %s\n", controller.URL)
	fmt.Printf("Client:     %s\n", client.URL)
	fmt.Printf("User:       %s\n", user.Username)
	fmt.Printf("Kubeconfig: %s (context: %s)\n", kubeconfigPath, "kind-"+kindClusterName)
	fmt.Printf("Start the Gateway with:\n")
	fmt.Printf("%s start --host twingate.local --network acme --tlsKey ../data/proxy/tls.key --tlsCert ../data/proxy/tls.crt --k8sAPIServerPort %d --k8sAPIServerCA ../data/api_server/tls.crt --k8sAPIServerToken %s --fakeControllerURL %s\n", os.Args[0], kindPort, kindBearerToken, controller.URL)
	fmt.Printf("Press Ctrl+C to stop\n")
	fmt.Printf("=====================================================\n\n")

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
  name: "alex@acme.com"
  apiGroup: rbac.authorization.k8s.io
`

func createKindCluster(logger *zap.Logger) error {
	provider := cluster.NewProvider(cluster.ProviderWithLogger(kindcmd.NewLogger()))

	existingClusters, err := provider.List()
	if err != nil {
		return err
	}

	// Check if the cluster already exists
	for _, cluster := range existingClusters {
		if cluster == kindClusterName {
			logger.Info("Cluster already exists", zap.String("cluster", kindClusterName))

			return nil
		}
	}

	logger.Info("Creating cluster", zap.String("cluster", kindClusterName))

	if err := provider.Create(kindClusterName, cluster.CreateWithRawConfig([]byte(kindClusterYaml))); err != nil {
		return err
	}

	k := &Kubectl{
		context: "kind-" + kindClusterName,
	}

	// It takes a while for KinD to create the `default` service account...
	logger.Info("Waiting for default service account to be created...")

	err = wait.PollUntilContextTimeout(context.Background(), time.Second, 30*time.Second, true, func(_ctx context.Context) (bool, error) {
		_, err = k.Command("get", "serviceaccount", "default")
		if err != nil {
			return false, nil //nolint:nilerr
		}

		return true, nil
	})
	if err != nil {
		logger.Fatal("Failed waiting for default service account", zap.Error(err))
	}

	_, err = k.WithInput(setupYaml).Command("apply", "-f", "-")
	if err != nil {
		logger.Fatal("Failed to apply setup YAML", zap.Error(err))
	}

	_, err = k.Command("wait", "--for=condition=Ready", "pod/test-pod", "--timeout=30s")
	if err != nil {
		logger.Fatal("Failed waiting for busybox pod", zap.Error(err))
	}

	return nil
}

func getKinDBearerToken() (string, error) {
	k := &Kubectl{
		context: "kind-" + kindClusterName,
	}

	b64BearerToken, err := k.Command("get", "secret", "gateway-default-service-account", "-o", "jsonpath={.data.token}")
	if err != nil {
		return "", err
	}

	bearerToken, err := base64.StdEncoding.DecodeString(string(b64BearerToken))
	if err != nil {
		return "", err
	}

	return string(bearerToken), nil
}

// updateKubeconfigFile creates a new kubeconfig file for the local dev environment.
func updateKubeconfigFile(serverURL string) error {
	// Create a minimal kubeconfig
	config := api.NewConfig()

	// Create cluster
	cluster := api.NewCluster()
	cluster.Server = serverURL
	cluster.InsecureSkipTLSVerify = true
	config.Clusters["twingate-gateway-local"] = cluster

	// Create auth info (no credentials needed as the fake client handles auth)
	authInfo := &api.AuthInfo{
		Token: "void",
	}
	config.AuthInfos["twingate-gateway-local"] = authInfo

	// Create context
	context := api.NewContext()
	context.Cluster = "twingate-gateway-local"
	context.AuthInfo = "twingate-gateway-local"
	config.Contexts["twingate-gateway-local"] = context

	// Set current context
	config.CurrentContext = "twingate-gateway-local"

	// Write the config to file
	return clientcmd.WriteToFile(*config, kubeconfigPath)
}

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
