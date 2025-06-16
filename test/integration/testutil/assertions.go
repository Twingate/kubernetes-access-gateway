package testutil

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
)

func AssertWhoAmI(t *testing.T, output []byte, expectedUsername string, expectedGroups []string) {
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

func AssertGetPods(t *testing.T, output []byte) {
	t.Helper()

	var podList corev1.PodList
	if err := json.Unmarshal(output, &podList); err != nil {
		t.Fatalf("Failed to parse kubectl get pods output: %v", err)
	}

	assert.Len(t, podList.Items, 1)
	assert.Equal(t, "test-pod", podList.Items[0].Name)
}

func AssertLogsForREST(t *testing.T, logs *observer.ObservedLogs, expectedURL string, expectedUser map[string]any) {
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

func AssertLogsForExec(t *testing.T, logs *observer.ObservedLogs, expectedURL, expectedOutput string, expectedUser map[string]any) {
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
