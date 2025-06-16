package testutil

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/kind/pkg/cluster"

	kindcmd "sigs.k8s.io/kind/pkg/cmd"
)

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
`

func SetupKinD(t *testing.T) (*Kubectl, *rest.Config, string) {
	t.Helper()

	provider := cluster.NewProvider(cluster.ProviderWithLogger(kindcmd.NewLogger()))
	clusterName := "gateway-integration-test-" + strings.ToLower(t.Name())

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
		options: KubectlOptions{
			context: "kind-" + clusterName,
		},
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

	_, err = k.CommandWithInput(setupYaml, "apply", "-f", "-")
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

func CreateK8sRoleBinding(t *testing.T, kindKubectl *Kubectl, users []string) {
	t.Helper()

	yaml := `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: gateway-test-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: edit
subjects:
`

	for _, user := range users {
		yaml += fmt.Sprintf(`- kind: User
  name: "%s"
  apiGroup: rbac.authorization.k8s.io
`, user)
	}

	_, err := kindKubectl.CommandWithInput(yaml, "apply", "-f", "-")
	if err != nil {
		t.Fatalf("Failed to apply setup YAML: %v", err)
	}
}
