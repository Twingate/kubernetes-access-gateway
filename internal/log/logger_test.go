// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package log

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name      string
		debug     bool
		wantLevel zapcore.Level
	}{
		{
			name:      "info level when debug is false",
			debug:     false,
			wantLevel: zapcore.InfoLevel,
		},
		{
			name:      "debug level when debug is true",
			debug:     true,
			wantLevel: zapcore.DebugLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewLogger("test-logger", tt.debug)
			require.NoError(t, err)
			require.NotNil(t, logger)
			assert.Equal(t, "test-logger", logger.Name())
			assert.Equal(t, tt.wantLevel, logger.Level())
		})
	}
}

func TestNewLogger_OutputFormat(t *testing.T) {
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stderr = w

	t.Cleanup(func() {
		os.Stderr = origStderr
	})

	logger, err := NewLogger("test-logger", false)
	require.NoError(t, err)

	logger.Info("hello world", zap.String("foo", "bar"))

	require.NoError(t, w.Close())

	output, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())

	line := strings.TrimSpace(string(output))
	require.NotEmpty(t, line)

	payload := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(line), &payload))

	assert.NotEmpty(t, payload["ts"])
	delete(payload, "ts")

	assert.Equal(t, map[string]any{
		"caller":    "log/logger_test.go:62",
		"logger":    "test-logger",
		"version":   "dev",
		"levelname": "info",
		"message":   "hello world",
		"foo":       "bar",
	}, payload)
}
