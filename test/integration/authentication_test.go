package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/stretchr/testify/assert"

	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/kind/pkg/cluster"

	kindcmd "sigs.k8s.io/kind/pkg/cmd"

	"k8sgateway/cmd"
	"k8sgateway/test/fake"
)

const network = "acme"

// Parse random port instead
const kindAPIServerPort = 54321

var kindClusterYaml = fmt.Sprintf(`
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerPort: %d
`, kindAPIServerPort)

func TestKubernetesAuthentication(t *testing.T) {
	provider := cluster.NewProvider(cluster.ProviderWithLogger(kindcmd.NewLogger()))
	clusterName := "k8s-gateway-test-integration"

	// Create the cluster
	//if err := provider.Create(clusterName, cluster.CreateWithRawConfig([]byte(kindClusterYaml))); err != nil {
	//	t.Fatalf("failed to create kind cluster: %v", err)
	//}
	//
	//defer func() {
	//	// Clean up the cluster after test
	//	if err := provider.Delete(clusterName, ""); err != nil {
	//		t.Errorf("failed to delete kind cluster: %v", err)
	//	}
	//}()

	// Get kubeconfig content for KinD context
	kubeConfigStr, err := provider.KubeConfig(clusterName, false)
	if err != nil {
		t.Fatalf("failed to get kubeconfig: %v", err)
	}

	kubeConfig, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeConfigStr))
	if err != nil {
		t.Fatalf("failed to build config from kubeconfig: %v", err)
	}

	t.Log("KinD cluster is ready at ", kubeConfig.Host)

	// Start controller
	controller := fake.NewController(network)
	defer controller.Close()
	t.Log("controller is serving at", controller.URL)

	// Get the root command
	rootCmd := cmd.GetRootCommand()
	rootCmd.SetArgs([]string{
		"start",
		"--host",
		"twingate.local",
		"--network",
		network,
		"--tlsKey",
		"../data/proxy/key.pem",
		"--tlsCert",
		"../data/proxy/cert.pem",
		"--k8sAPIServerPort",
		strconv.Itoa(kindAPIServerPort),
		"--k8sAPIServerCAData",
		string(kubeConfig.CAData),
		"--k8sGatewayCertData",
		string(kubeConfig.CertData),
		"--k8sGatewayKeyData",
		string(kubeConfig.KeyData),
		"--fakeControllerURL",
		controller.URL,
	})

	go func() {
		// TODO: need to gracefully stop the proxy
		err = rootCmd.Execute()
		t.Logf("Failed to start Gateway: %v", err)
	}()

	gatewayHealthCheck(t)

	// Setup a test logger to capture log output
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	logger.Named("test")

	// Replace the global logger
	originalLogger := zap.L()
	zap.ReplaceGlobals(logger)
	defer fmt.Println(logs.All())
	defer zap.ReplaceGlobals(originalLogger) // Restore original logger

	// Create client
	fake.NewClient("127.0.0.1:8443", controller.URL, kubeConfig.Host)
	//defer client.Close()

	// Set up context with timeout
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel() // Create cluster role binding for the test user

	t.Log("Creating cluster role binding for alex@acme.com...")
	//kubectlCreateRoleBinding := exec.CommandContext(ctx, "kubectl", "--context=kind-k8s-gateway-test-integration", "create", "clusterrolebinding",
	//	"test-user-binding",
	//	"--clusterrole=edit",
	//	"--user=alex@acme.com")
	//if roleBindingOutput, err := kubectlCreateRoleBinding.CombinedOutput(); err != nil {
	//	t.Fatalf("Failed to create cluster role binding: %v, output: %s", err, string(roleBindingOutput))
	//}

	// TODO: make sure serviceacount/default is ready

	// Start a busybox pod to test kubectl access
	t.Log("Starting a busybox pod for testing kubectl access...")
	kubectlCreateBusybox := exec.CommandContext(ctx, "kubectl", "--context=kind-k8s-gateway-test-integration", "run", "busybox", "--image=busybox", "--restart=Never", "--", "sleep", "3600")
	if busyboxOutput, err := kubectlCreateBusybox.CombinedOutput(); err != nil {
		t.Fatalf("Failed to create busybox pod: %v, output: %s", err, string(busyboxOutput))
	}

	// Wait for the pod to be ready
	t.Log("Waiting for busybox pod to be ready...")
	kubectlWaitPod := exec.CommandContext(ctx, "kubectl", "wait", "--for=condition=Ready", "pod/busybox", "--timeout=60s")
	if waitOutput, err := kubectlWaitPod.CombinedOutput(); err != nil {
		t.Fatalf("Failed waiting for busybox pod: %v, output: %s", err, string(waitOutput))
	}

	t.Log("Busybox pod is ready")

	// Configure kubectl to use our proxy
	kubectlSetCluster := exec.CommandContext(ctx, "kubectl", "config", "set-cluster", "gateway-integration-test",
		"--certificate-authority=../data/proxy/cert.pem",
		"--server=https://127.0.0.1:9000")

	if setClusterOutput, err := kubectlSetCluster.CombinedOutput(); err != nil {
		t.Fatalf("Failed to configure kubectl: %v, output: %s", err, string(setClusterOutput))
	}

	kubectlSetUser := exec.CommandContext(ctx, "kubectl", "config", "set-credentials", "gateway-integration-test", "--token=void")

	if setUserOutput, err := kubectlSetUser.CombinedOutput(); err != nil {
		t.Fatalf("Failed to configure kubectl: %v, output: %s", err, string(setUserOutput))
	}

	kubectlSetContext := exec.CommandContext(ctx, "kubectl", "config", "set-context", "gateway-integration-test", "--cluster=gateway-integration-test", "--user=gateway-integration-test")

	if setContextOutput, err := kubectlSetContext.CombinedOutput(); err != nil {
		t.Fatalf("Failed to configure kubectl: %v, output: %s", err, string(setContextOutput))
	}

	kubectlSetCurrentContext := exec.CommandContext(ctx, "kubectl", "config", "use-context", "gateway-integration-test")

	if setCurrentContextOutput, err := kubectlSetCurrentContext.CombinedOutput(); err != nil {
		t.Fatalf("Failed to configure kubectl: %v, output: %s", err, string(setCurrentContextOutput))
	}

	t.Log("Successfully configured kubectl to use gateway proxy")

	// Execute kubectl auth whoami with JSON output
	cmd := exec.CommandContext(ctx, "kubectl", "auth", "whoami", "-o", "json")

	output, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			t.Fatalf("kubectl auth whoami failed with stderr: %s", string(exitError.Stderr))
		}
		t.Fatalf("Failed to execute kubectl auth whoami: %v", err)
	}

	// Parse JSON output using official Kubernetes types
	var whoami authv1.SelfSubjectReview
	if err := json.Unmarshal(output, &whoami); err != nil {
		t.Fatalf("Failed to parse kubectl auth whoami output: %v", err)
	}

	// Assert API server receives correct identity
	username := whoami.Status.UserInfo.Username
	groups := whoami.Status.UserInfo.Groups
	assert.Equal(t, "alex@acme.com", username)
	assert.Equal(t, []string{"OnCall", "Engineering", "system:authenticated"}, groups)

	//assert.Equal(t, logs.Len(), 10)

	// Test kubectl exec into the busybox pod
	t.Log("Testing kubectl exec into busybox pod...")
	// kubectlExec := exec.CommandContext(ctx, "kubectl", "exec", "-it", "busybox", "--", "/bin/sh", "-c", "echo 'Hello from busybox'")
	kubectlExec := exec.CommandContext(ctx, "kubectl", "exec", "-it", "busybox", "--", "cat", "/etc/hostname")
	if execOutput, err := kubectlExec.CombinedOutput(); err != nil {
		t.Fatalf("Failed to exec into busybox pod: %v, output: %s", err, string(execOutput))
	}
	t.Log("Successfully executed command in busybox pod")

	// TODO: assert exec output
}

func gatewayHealthCheck(t *testing.T) {
	t.Helper()
	t.Log("Waiting for Gateway to be ready...")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip certificate verification for the health check
			},
		},
		Timeout: 200 * time.Millisecond,
	}

	// Try to connect to the health endpoint with fixed backoff
	backoff := 100 * time.Millisecond
	maxAttempts := 5
	gatewayURL := "https://127.0.0.1:8443/healthz"

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := client.Get(gatewayURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			t.Log("Gateway is ready at", "127.0.0.1:8443")

			break
		}

		if resp != nil {
			resp.Body.Close()
		}

		if attempt == maxAttempts {
			t.Fatalf("Gateway failed to start after %d attempts", maxAttempts)
		}

		time.Sleep(backoff)
	}
}
