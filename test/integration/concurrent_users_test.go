package integration

import (
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"k8sgateway/cmd"
	"k8sgateway/internal/token"
	"k8sgateway/test/fake"
	"k8sgateway/test/integration/testutil"
)

const numUsers = 10

func TestConcurrentUsers(t *testing.T) {
	const gatewayPort = 8444

	kindKubectl, kindKubeConfig, kindBearerToken := testutil.SetupKinD(t)

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
			"--port",
			strconv.Itoa(gatewayPort),
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

	testutil.GatewayHealthCheck(t, gatewayPort)

	// Set up a test logger to capture log output
	// This must be done after the proxy is started because
	// the proxy also set the global logger.
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	logger.Named("test")

	originalLogger := zap.L()
	zap.ReplaceGlobals(logger)

	defer zap.ReplaceGlobals(originalLogger) // Restore original logger

	var users = make([]*testutil.User, 0, numUsers)

	var usersNames = make([]string, 0, numUsers)

	for i := range numUsers {
		user, err := testutil.NewUser(
			&token.User{
				ID:       fmt.Sprintf("user-%d", i+1),
				Username: fmt.Sprintf("user-%d@acme.com", i+1),
				Groups:   []string{},
			},
			gatewayPort,
			kindKubeConfig.Host,
			controller.URL,
		)
		if err != nil {
			t.Fatalf("Failed to create user %d: %v", i+1, err)
		}

		users = append(users, user)
		usersNames = append(usersNames, user.Username)
	}

	defer func() {
		for _, user := range users {
			user.Close()
		}
	}()

	testutil.CreateK8sRoleBinding(t, kindKubectl, usersNames)

	wg := sync.WaitGroup{}

	for i, user := range users {
		wg.Add(1)

		go func() {
			t.Log("User", i+1, "is running", user.Username)
			// Test `kubectl auth whoami`
			output, err := user.Kubectl.Command("auth", "whoami", "-o", "json")
			if err != nil {
				t.Logf("Failed to execute kubectl auth whoami: %v", err)
			}

			testutil.AssertWhoAmI(t, output, user.Username, append(user.Groups, "system:authenticated"))

			// Test `kubectl get pods`
			output, err = user.Kubectl.Command("get", "pods", "-o", "json")
			if err != nil {
				t.Logf("Failed to execute kubectl get pods: %v", err)
			}

			testutil.AssertGetPods(t, output)

			// Test `kubectl exec`
			output, err = user.Kubectl.Command("exec", "test-pod", "--", "cat", "/etc/hostname")
			if err != nil {
				t.Logf("Failed to execute kubectl exec: %v", err)
			}

			assert.Equal(t, "test-pod\n", string(output))

			// Asserting logs
			expectedUser := map[string]any{
				"id":       user.ID,
				"username": user.Username,
				"groups":   []any{},
			}
			userLogs := logs.FilterField(zap.Object("user", user.User))
			testutil.AssertLogsForREST(t, userLogs, "/apis/authentication.k8s.io/v1/selfsubjectreviews", expectedUser)
			testutil.AssertLogsForExec(t, userLogs, "/api/v1/namespaces/default/pods/test-pod/exec?command=cat&command=%2Fetc%2Fhostname&container=test-pod&stderr=true&stdout=true", "test-pod", expectedUser)

			wg.Done()
		}()
	}

	wg.Wait()
}
