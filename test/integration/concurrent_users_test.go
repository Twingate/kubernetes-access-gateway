package integration

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"k8sgateway/cmd"
	"k8sgateway/internal/token"
	"k8sgateway/test/fake"
	"k8sgateway/test/integration/testutil"
)

const numUsers = 10

// TestConcurrentUsers tests that multiple users can access the gateway concurrently
// and that their identities are correctly forwarded to the Kubernetes API server and logged.
//
// Each user run its own goroutine. A list of pre-defined commands is shuffled and run sequentially.
// The output and audit log of each command is asserted.
func TestConcurrentUsers(t *testing.T) {
	const gatewayPort = 8444

	kindKubectl, kindKubeConfig, kindBearerToken := testutil.SetupKinD(t)

	kindURL, err := url.Parse(kindKubeConfig.Host)
	require.NoError(t, err, "failed to parse API server URL")

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
			"--metricsPort",
			"0",
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
		require.NoError(t, err, "failed to create user %d", i+1)

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

	for _, user := range users {
		wg.Add(1)

		go func() {
			expectedUser := map[string]any{
				"id":       user.ID,
				"username": user.Username,
				"groups":   []any{},
			}

			commands := []command{
				{
					name: "whoami",
					args: []string{"auth", "whoami", "-o", "json"},
					assertOutputFn: func(t *testing.T, output []byte) {
						t.Helper()
						testutil.AssertWhoAmI(t, output, user.Username, []string{"system:authenticated"})
					},
					assertLogFn: func(t *testing.T, logs *observer.ObservedLogs) {
						t.Helper()
						testutil.AssertLogsForREST(t, logs, "/apis/authentication.k8s.io/v1/selfsubjectreviews", expectedUser, http.StatusCreated)
					},
				},
				{
					name:           "get-pods",
					args:           []string{"get", "pods", "-o", "json"},
					assertOutputFn: testutil.AssertGetPods,
					assertLogFn: func(t *testing.T, logs *observer.ObservedLogs) {
						t.Helper()
						testutil.AssertLogsForREST(t, logs, "/api/v1/namespaces/default/pods?limit=500", expectedUser, http.StatusOK)
					},
				},
				{
					name: "exec-sleep",
					args: []string{"exec", "test-pod", "--", "sleep", "2"},
					assertOutputFn: func(t *testing.T, output []byte) {
						t.Helper()
						assert.Empty(t, string(output))
					},
					assertLogFn: func(t *testing.T, logs *observer.ObservedLogs) {
						t.Helper()
						testutil.AssertLogsForExec(t, logs, "/api/v1/namespaces/default/pods/test-pod/exec?command=sleep&command=2&container=test-pod&stderr=true&stdout=true", "", expectedUser)
					},
				},
				{
					name: "exec-cat",
					args: []string{"exec", "test-pod", "--", "cat", "/etc/hostname"},
					assertOutputFn: func(t *testing.T, output []byte) {
						t.Helper()
						assert.Equal(t, "test-pod\n", string(output))
					},
					assertLogFn: func(t *testing.T, logs *observer.ObservedLogs) {
						t.Helper()
						testutil.AssertLogsForExec(t, logs, "/api/v1/namespaces/default/pods/test-pod/exec?command=cat&command=%2Fetc%2Fhostname&container=test-pod&stderr=true&stdout=true", "test-pod", expectedUser)
					},
				},
			}
			rand.Shuffle(len(commands), func(i, j int) {
				commands[i], commands[j] = commands[j], commands[i]
			})

			t.Logf("User %s is running commands: %s", user.ID, commands)

			lastLogTime := time.Time{}

			for _, cmd := range commands {
				output, err := user.Kubectl.Command(cmd.args...)
				if err != nil {
					t.Logf("Failed to run kubectl %s: %v", cmd.name, err)
				}

				cmd.assertOutputFn(t, output)

				// Wait for the logs to be flushed
				time.Sleep(100 * time.Millisecond)

				// Get user logs since last command
				userLogs := logs.Filter(func(e observer.LoggedEntry) bool {
					if !e.Time.After(lastLogTime) {
						return false
					}

					for _, ctxField := range e.Context {
						if ctxField.Equals(zap.Object("user", user.User)) {
							return true
						}
					}

					return false
				})
				cmd.assertLogFn(t, userLogs)
				lastLogTime = userLogs.All()[len(userLogs.All())-1].Time
			}

			wg.Done()
		}()
	}

	wg.Wait()
}

type command struct {
	name           string
	args           []string
	assertOutputFn func(t *testing.T, output []byte)
	assertLogFn    func(t *testing.T, logs *observer.ObservedLogs)
}

func (c command) String() string {
	return c.name
}
