package integration

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/kind/pkg/cluster"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kindcmd "sigs.k8s.io/kind/pkg/cmd"

	"k8sgateway/cmd"
	"k8sgateway/test/fake"
)

const network = "acme"
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
	if err := provider.Create(clusterName, cluster.CreateWithRawConfig([]byte(kindClusterYaml))); err != nil {
		t.Fatalf("failed to create kind cluster: %v", err)
	}

	defer func() {
		// Clean up the cluster after test
		if err := provider.Delete(clusterName, ""); err != nil {
			t.Errorf("failed to delete kind cluster: %v", err)
		}
	}()

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

	// Create client
	client := fake.NewClient("127.0.0.1:8443", controller.URL, kubeConfig.Host)
	if client == nil {
		t.Fatalf("failed to create clientset")
	}
	defer client.Close()

	result, err := client.AuthenticationV1().SelfSubjectReviews().Create(
		t.Context(),
		&authenticationv1.SelfSubjectReview{},
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatalf("Failed to create self subject review: %v", err)
	}

	// Assert API server receives correct identity
	username := result.Status.UserInfo.Username
	groups := result.Status.UserInfo.Groups

	assert.Equal(t, "alex@acme.com", username)
	assert.Equal(t, []string{"OnCall", "Product Engineer", "system:authenticated"}, groups)
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
