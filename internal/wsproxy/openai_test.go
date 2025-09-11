// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package wsproxy

import (
    "bytes"
    "encoding/json"
    "io/ioutil"
    "net/http"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// roundTripperFunc allows stubbing http.DefaultClient.Transport in tests.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSummarizeAsciicastWithOpenAI_Disabled_ReturnsEmpty(t *testing.T) {
    t.Setenv("GATEWAY_AI_SUMMARY_ENABLED", "0")
    t.Setenv("OPENAI_API_KEY", "")

    got := summarizeAsciicastWithOpenAI("anything")
    assert.Equal(t, "", got)
}

func TestSummarizeAsciicastWithOpenAI_NoAPIKey_ReturnsEmpty(t *testing.T) {
    t.Setenv("GATEWAY_AI_SUMMARY_ENABLED", "true")
    t.Setenv("OPENAI_API_KEY", "")

    got := summarizeAsciicastWithOpenAI("anything")
    assert.Equal(t, "", got)
}

func TestSummarizeAsciicastWithOpenAI_Success_ReturnsSummary(t *testing.T) {
    t.Setenv("GATEWAY_AI_SUMMARY_ENABLED", "true")
    t.Setenv("OPENAI_API_KEY", "sk-test")
    t.Setenv("OPENAI_MODEL", "gpt-test")

    // Stub network call
    prev := http.DefaultClient.Transport
    t.Cleanup(func() { http.DefaultClient.Transport = prev })

    http.DefaultClient.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
        // Verify endpoint and headers are present
        require.Equal(t, "https://api.openai.com/v1/chat/completions", r.URL.String())
        require.Equal(t, "Bearer sk-test", r.Header.Get("Authorization"))

        // Inspect payload shape
        var payload struct {
            Model    string                   `json:"model"`
            Messages []map[string]string      `json:"messages"`
            Max      int                      `json:"max_tokens"`
        }
        body, _ := ioutil.ReadAll(r.Body)
        _ = r.Body.Close()
        require.NoError(t, json.Unmarshal(body, &payload))
        assert.Equal(t, "gpt-test", payload.Model)
        require.GreaterOrEqual(t, len(payload.Messages), 2)

        // Return a minimal successful response
        respBody := `{"choices":[{"message":{"content":"user ran kubectl get pods"}}]}`
        return &http.Response{
            StatusCode: 200,
            Body:       ioutil.NopCloser(bytes.NewBufferString(respBody)),
            Header:     make(http.Header),
        }, nil
    })

    got := summarizeAsciicastWithOpenAI("header\n[0.1, \"o\", \"kubectl get pods\"]")
    assert.Equal(t, "user ran kubectl get pods", got)
}

func TestSummarizeAsciicastWithOpenAI_Non200_ReturnsEmpty(t *testing.T) {
    t.Setenv("GATEWAY_AI_SUMMARY_ENABLED", "true")
    t.Setenv("OPENAI_API_KEY", "sk-test")

    prev := http.DefaultClient.Transport
    t.Cleanup(func() { http.DefaultClient.Transport = prev })

    http.DefaultClient.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
        return &http.Response{StatusCode: 500, Body: ioutil.NopCloser(bytes.NewBuffer(nil)), Header: make(http.Header)}, nil
    })

    got := summarizeAsciicastWithOpenAI("data")
    assert.Equal(t, "", got)
}

