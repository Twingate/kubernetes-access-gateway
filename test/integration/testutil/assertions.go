// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
)

type asciicastHeader struct {
	Version int `json:"version"`
	Width   int `json:"width"`
	Height  int `json:"height"`
}

func AssertWhoAmI(t *testing.T, output []byte, expectedUsername string, expectedGroups []string) {
	t.Helper()

	var whoami authv1.SelfSubjectReview

	err := json.Unmarshal(output, &whoami)
	require.NoError(t, err, "failed to parse kubectl auth whoami output")

	username := whoami.Status.UserInfo.Username
	groups := whoami.Status.UserInfo.Groups

	assert.Equal(t, expectedUsername, username)
	assert.Equal(t, expectedGroups, groups)
}

func AssertGetPods(t *testing.T, output []byte) {
	t.Helper()

	var podList corev1.PodList

	err := json.Unmarshal(output, &podList)
	require.NoError(t, err, "failed to parse kubectl get pods output")

	assert.Len(t, podList.Items, 1)
	assert.Equal(t, "test-pod", podList.Items[0].Name)
}

func AssertLogsForREST(t *testing.T, logs *observer.ObservedLogs, expectedURL string, expectedUser map[string]any, expectedStatusCode int) {
	t.Helper()

	expectedLogs := logs.FilterField(zap.String("url", expectedURL)).All()
	assert.Len(t, expectedLogs, 1, "expected 1 log for URL %s, user %v", expectedURL, expectedUser)

	firstLog := expectedLogs[0]
	assert.Equal(t, "API request completed", firstLog.Message)
	assert.Equal(t, expectedUser, firstLog.ContextMap()["user"])
	assert.Subset(t, firstLog.ContextMap()["response"], map[string]any{"status_code": expectedStatusCode})
}

func AssertLogsForExec(t *testing.T, logs *observer.ObservedLogs, expectedURL, expectedOutput string, expectedUser map[string]any) {
	t.Helper()

	expectedLogs := logs.FilterField(zap.String("url", expectedURL)).All()
	assert.Len(t, expectedLogs, 2, "expected 2 logs for URL %s, user %v", expectedURL, expectedUser)

	firstLog := expectedLogs[0]
	assert.Equal(t, "session finished", firstLog.Message)
	assert.Equal(t, expectedUser, firstLog.ContextMap()["user"])
	assert.Contains(t, firstLog.ContextMap()["asciicast"], expectedOutput)

	// Validate asciicast header and event
	asciicast, ok := firstLog.ContextMap()["asciicast"].(string)
	require.True(t, ok, "asciicast should be a string")
	AssertValidAsciicast(t, asciicast, expectedOutput)

	secondLog := expectedLogs[1]
	assert.Equal(t, "API request completed", secondLog.Message)
	assert.Equal(t, expectedUser, secondLog.ContextMap()["user"])
	assert.Subset(t, secondLog.ContextMap()["response"], map[string]any{"status_code": http.StatusSwitchingProtocols})

	// Request and response logs must have the same request ID
	assert.Equal(t, firstLog.ContextMap()["request_id"], secondLog.ContextMap()["request_id"])
}

func AssertValidAsciicast(t *testing.T, asciicast string, expectedOutput string) {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(asciicast), "\n")
	require.Len(t, lines, 3, "asciicast should have 3 lines")

	headerLine := lines[0]
	assertAsciicastHeader(t, headerLine, 0, 0)

	firstEventLine := lines[1]
	assertAsciicastEvent(t, firstEventLine, "o", "")

	secondEventLine := lines[2]
	assertAsciicastEvent(t, secondEventLine, "o", expectedOutput)
}

func assertAsciicastHeader(t *testing.T, headerLine string, expectedWidth int, expectedHeight int) {
	t.Helper()

	var header asciicastHeader

	err := json.Unmarshal([]byte(headerLine), &header)
	require.NoError(t, err)

	assert.Equal(t, 2, header.Version)
	assert.Equal(t, expectedWidth, header.Width)
	assert.Equal(t, expectedHeight, header.Height)
}

func assertAsciicastEvent(t *testing.T, eventLine string, expectedEventType string, expectedData string) {
	t.Helper()

	var event []any

	err := json.Unmarshal([]byte(eventLine), &event)
	require.NoError(t, err)
	require.Len(t, event, 3, "event must have 3 elements")

	// First element is time (float)
	_, ok := event[0].(float64)
	assert.True(t, ok, "first element should be a float (time)")

	// Second element is event type
	assert.Equal(t, expectedEventType, event[1], "second element should be %s", expectedEventType)

	// Third element is the data
	eventData, ok := event[2].(string)
	assert.True(t, ok, "third element should be a string")
	assert.Equal(t, expectedData, strings.TrimSpace(eventData), "third element should be %s", expectedData)
}
