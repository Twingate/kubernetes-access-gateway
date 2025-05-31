package integration

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/kind/pkg/cluster"

	authv1 "k8s.io/api/authentication/v1"
	kindcmd "sigs.k8s.io/kind/pkg/cmd"

	"k8sgateway/cmd"
	"k8sgateway/internal/token"
	"k8sgateway/test/fake"
)

const network = "acme"

const kindClusterYaml = `
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
    - hostPath: ../data/api_server/tls.crt
      containerPath: /etc/kubernetes/pki/ca.crt
    - hostPath: ../data/api_server/tls.key
      containerPath: /etc/kubernetes/pki/ca.key
`

func TestKubernetesAuthentication(t *testing.T) {
	kindKubectl, kindKubeConfig, kindBearerToken := setupKinD(t)

	kindURL, err := url.Parse(kindKubeConfig.Host)
	if err != nil {
		t.Fatalf("Failed to parse API server URL: %v", err)
	}

	// Start the Controller
	controller := fake.NewController(network)
	defer controller.Close()
	t.Log("Controller is serving at", controller.URL)

	// Start the Gateway
	go func() {
		rootCmd := cmd.GetRootCommand()
		rootCmd.SetArgs([]string{
			"start",
			"--host",
			"twingate.local",
			"--network",
			network,
			"--tlsKey",
			"../data/proxy/tls.key",
			"--tlsCert",
			"../data/proxy/tls.crt",
			"--k8sAPIServerPort",
			kindURL.Port(),
			"--k8sAPIServerCA",
			"../data/api_server/tls.crt",
			"--k8sAPIServerToken",
			kindBearerToken,
			"--fakeControllerURL",
			controller.URL,
		})

		err := rootCmd.Execute()
		t.Logf("Failed to start Gateway: %v", err)
	}()

	gatewayHealthCheck(t)

	// Setup a test logger to capture log output
	// This must be done after the proxy is started because
	// the proxy also set the global logger.
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	logger.Named("test")

	originalLogger := zap.L()
	zap.ReplaceGlobals(logger)

	defer zap.ReplaceGlobals(originalLogger) // Restore original logger

	// Start a client
	user := &token.User{
		ID:       "user-1",
		Username: "alex@acme.com",
		Groups:   []string{"OnCall", "Engineering"},
	}

	client := fake.NewClient(
		user,
		"127.0.0.1:8443",
		controller.URL,
		kindKubeConfig.Host,
	)
	defer client.Close()

	clientKubectl := createClientKubectl(t, kindKubectl, client.URL)

	// Test `kubectl auth whoami`
	output, err := clientKubectl.Command("auth", "whoami", "-o", "json")
	if err != nil {
		t.Fatalf("Failed to execute kubectl auth whoami: %v", err)
	}

	assertWhoAmI(t, output, user.Username, append(user.Groups, "system:authenticated"))

	expectedUser := map[string]any{
		"id":       "user-1",
		"username": "alex@acme.com",
		"groups":   []any{"OnCall", "Engineering"},
	}
	assertLogsForREST(t, logs, "/apis/authentication.k8s.io/v1/selfsubjectreviews", expectedUser)

	// Test `kubectl exec`
	output, err = clientKubectl.Command("exec", "test-pod", "--", "cat", "/etc/hostname")
	if err != nil {
		t.Fatalf("Failed to execute kubectl exec: %v", err)
	}

	assert.Equal(t, "test-pod\n", string(output))
	assertLogsForExec(t, logs, "/api/v1/namespaces/default/pods/test-pod/exec?command=cat&command=%2Fetc%2Fhostname&container=test-pod&stderr=true&stdout=true", "test-pod", expectedUser)
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

func setupKinD(t *testing.T) (*Kubectl, *rest.Config, string) {
	t.Helper()

	provider := cluster.NewProvider(cluster.ProviderWithLogger(kindcmd.NewLogger()))
	clusterName := "gateway-integration-test"

	// Create the cluster
	if err := provider.Create(clusterName, cluster.CreateWithRawConfig([]byte(kindClusterYaml))); err != nil {
		t.Fatalf("failed to create kind cluster: %v", err)
	}

	t.Cleanup(func() {
		if err := provider.Delete(clusterName, ""); err != nil {
			t.Errorf("failed to delete kind cluster: %v", err)
		}
	})

	// Get kubeconfig for KinD context
	kubeConfigStr, err := provider.KubeConfig(clusterName, false)
	if err != nil {
		t.Fatalf("failed to get kubeconfig: %v", err)
	}

	kubeConfig, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeConfigStr))
	if err != nil {
		t.Fatalf("failed to build config from kubeconfig: %v", err)
	}

	t.Log("KinD cluster was created at ", kubeConfig.Host)

	k := &Kubectl{
		context: "kind-" + clusterName,
	}

	// It takes a while for KinD to create the `default` service account...
	t.Log("Waiting for default service account to be created...")

	err = wait.PollUntilContextTimeout(t.Context(), time.Second, 30*time.Second, true, func(_ctx context.Context) (bool, error) {
		_, err = k.Command("get", "serviceaccount", "default")
		if err != nil {
			return false, nil //nolint:nilerr
		}

		return true, nil
	})
	if err != nil {
		t.Fatalf("Failed waiting for default service account: %v", err)
	}

	_, err = k.WithInput(setupYaml).Command("apply", "-f", "-")
	if err != nil {
		t.Fatalf("Failed to apply setup YAML: %v", err)
	}

	b64BearerToken, err := k.Command("get", "secret", "gateway-default-service-account", "-o", "jsonpath={.data.token}")
	if err != nil {
		t.Fatalf("Failed to get default service account's bearer token: %v", err)
	}

	bearerToken, err := base64.StdEncoding.DecodeString(string(b64BearerToken))
	if err != nil {
		t.Fatalf("Failed to decode bearer token: %v", err)
	}

	t.Log("Waiting for test-pod to be ready...")

	_, err = k.Command("wait", "--for=condition=Ready", "pod/test-pod", "--timeout=30s")
	if err != nil {
		t.Fatalf("Failed waiting for busybox pod: %v", err)
	}

	return k, kubeConfig, string(bearerToken)
}

// Create a Kubectl instance that mimics the end-user's kubectl CLI
//
// This Kubectl instance uses a kubecontext that points to the mock client.
func createClientKubectl(t *testing.T, kindKubectl *Kubectl, clientURL string) *Kubectl {
	t.Helper()

	contextName := "gateway-integration-test-mock-client"

	t.Cleanup(func() {
		_, err := kindKubectl.Command("config", "delete-context", contextName)
		if err != nil {
			t.Errorf("Failed to delete context %s: %v", contextName, err)
		}

		_, err = kindKubectl.Command("config", "delete-cluster", contextName)
		if err != nil {
			t.Errorf("Failed to delete cluster %s: %v", contextName, err)
		}

		_, err = kindKubectl.Command("config", "delete-user", contextName)
		if err != nil {
			t.Errorf("Failed to delete user %s: %v", contextName, err)
		}
	})

	_, err := kindKubectl.Command("config", "set-cluster", contextName,
		"--certificate-authority=../data/proxy/tls.crt",
		"--server="+clientURL,
	)
	if err != nil {
		t.Fatalf("Failed to configure kubectl: %v", err)
	}

	_, err = kindKubectl.Command("config", "set-credentials", contextName, "--token=void")
	if err != nil {
		t.Fatalf("Failed to configure kubectl: %v", err)
	}

	_, err = kindKubectl.Command("config", "set-context", contextName, "--cluster="+contextName, "--user="+contextName)
	if err != nil {
		t.Fatalf("Failed to configure kubectl: %v", err)
	}

	return &Kubectl{
		context: contextName,
	}
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

func assertWhoAmI(t *testing.T, output []byte, expectedUsername string, expectedGroups []string) {
	t.Helper()

	var whoami authv1.SelfSubjectReview
	if err := json.Unmarshal(output, &whoami); err != nil {
		t.Fatalf("Failed to parse kubectl auth whoami output: %v", err)
	}

	username := whoami.Status.UserInfo.Username
	groups := whoami.Status.UserInfo.Groups

	assert.Equal(t, expectedUsername, username)
	assert.Equal(t, expectedGroups, groups)
}

func assertLogsForREST(t *testing.T, logs *observer.ObservedLogs, expectedURL string, expectedUser map[string]any) {
	t.Helper()

	expectedLogs := logs.FilterField(zap.String("url", expectedURL)).All()
	assert.Len(t, expectedLogs, 2)

	firstLog := expectedLogs[0]
	assert.Equal(t, "API request", firstLog.Message)
	assert.Equal(t, expectedUser, firstLog.ContextMap()["user"])
	assert.NotEmpty(t, firstLog.ContextMap()["request"])

	secondLog := expectedLogs[1]
	assert.Equal(t, "API response", secondLog.Message)
	assert.Equal(t, expectedUser, secondLog.ContextMap()["user"])
	assert.NotEmpty(t, secondLog.ContextMap()["response"])

	// Request and response logs must have the same request ID
	assert.Equal(t, firstLog.ContextMap()["request_id"], secondLog.ContextMap()["request_id"])
}

func assertLogsForExec(t *testing.T, logs *observer.ObservedLogs, expectedURL, expectedOutput string, expectedUser map[string]any) {
	t.Helper()

	expectedLogs := logs.FilterField(zap.String("url", expectedURL)).All()
	assert.Len(t, expectedLogs, 2)

	firstLog := expectedLogs[0]
	assert.Equal(t, "API request", firstLog.Message)
	assert.Equal(t, expectedUser, firstLog.ContextMap()["user"])

	secondLog := expectedLogs[1]
	assert.Equal(t, "session finished", secondLog.Message)
	assert.Equal(t, expectedUser, secondLog.ContextMap()["user"])
	assert.Contains(t, secondLog.ContextMap()["asciinema_data"], expectedOutput)

	// Request and response logs must have the same request ID
	assert.Equal(t, firstLog.ContextMap()["request_id"], secondLog.ContextMap()["request_id"])
}
