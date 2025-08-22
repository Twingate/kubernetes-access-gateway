// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"crypto/tls"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"k8sgateway/test/data"
)

const (
	certFile = "../../test/data/proxy/tls.crt"
	keyFile  = "../../test/data/proxy/tls.key"
)

func TestReloadWhenFileChanged(t *testing.T) {
	certReloader := newCertReloader(certFile, keyFile, zap.NewNop())

	certReloader.run()
	defer certReloader.stop()

	time.Sleep(5 * time.Millisecond)

	updateCertFiles(t, "../../test/data/proxy/tls1.crt", "../../test/data/proxy/tls1.key")
	time.Sleep(5 * time.Millisecond)

	hello := &tls.ClientHelloInfo{}

	newCert, err := certReloader.getCertificate(hello)
	require.NoError(t, err)

	expectedCert, err := tls.X509KeyPair(data.ProxyCert1, data.ProxyKey1)
	require.NoError(t, err)

	assert.Equal(t, expectedCert.Certificate, newCert.Certificate)

	// Ensure cert and key files are still being watched
	watchList := certReloader.watcher.WatchList()
	assert.ElementsMatch(t, watchList, []string{certFile, keyFile})
}

func TestDontReloadWhenInvalidKeyPair(t *testing.T) {
	certReloader := newCertReloader(certFile, keyFile, zap.NewNop())

	certReloader.run()
	defer certReloader.stop()

	time.Sleep(5 * time.Millisecond)

	// Invalid key pair
	updateCertFiles(t, "../../test/data/proxy/tls1.crt", "../../test/data/proxy/tls.key")
	time.Sleep(5 * time.Millisecond)

	hello := &tls.ClientHelloInfo{}

	newCert, err := certReloader.getCertificate(hello)
	require.NoError(t, err)

	expectedCert, err := tls.X509KeyPair(data.ProxyCert, data.ProxyKey)
	require.NoError(t, err)

	// Ensure certificate is unchanged
	assert.Equal(t, expectedCert.Certificate, newCert.Certificate)

	// Ensure cert and key files are still being watched
	watchList := certReloader.watcher.WatchList()
	assert.ElementsMatch(t, watchList, []string{certFile, keyFile})
}

func TestStop(t *testing.T) {
	certReloader := newCertReloader(certFile, keyFile, zap.NewNop())
	certReloader.run()
	time.Sleep(5 * time.Millisecond)

	certReloader.stop()

	updateCertFiles(t, "../../test/data/proxy/tls1.crt", "../../test/data/proxy/tls1.key")
	time.Sleep(5 * time.Millisecond)

	expectedCert, err := tls.X509KeyPair(data.ProxyCert, data.ProxyKey)
	require.NoError(t, err)

	hello := &tls.ClientHelloInfo{}

	newCert, err := certReloader.getCertificate(hello)
	require.NoError(t, err)

	assert.Equal(t, expectedCert.Certificate, newCert.Certificate)

	watchList := certReloader.watcher.WatchList()
	assert.Empty(t, watchList)
}

func TestErrorInitializeCertReloader(t *testing.T) {
	tests := []struct {
		name               string
		setup              func(logger *zap.Logger) *certReloader
		expectedLogMessage string
	}{
		{
			name: "invalid cert file",
			setup: func(logger *zap.Logger) *certReloader {
				return newCertReloader("foo.crt", keyFile, logger)
			},
		},
		{
			name: "invalid key file",
			setup: func(logger *zap.Logger) *certReloader {
				return newCertReloader(certFile, "foo.key", logger)
			},
		},
		{
			name: "invalid key pair",
			setup: func(logger *zap.Logger) *certReloader {
				return newCertReloader(certFile, "../../test/data/proxy/tls1.key", logger)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			logger := zap.New(core)

			certReloader := tt.setup(logger)

			certReloader.run()
			defer certReloader.stop()

			time.Sleep(5 * time.Millisecond)

			log := logs.All()[0]
			assert.Equal(t, zapcore.ErrorLevel, log.Level)
			assert.Equal(t, log.Message, "failed to watch cert and key file, will retry later")
		})
	}
}

func updateCertFiles(t *testing.T, newCert, newKey string) {
	t.Helper()

	originalCert := data.ProxyCert
	originalKey := data.ProxyKey

	err := os.Rename(newCert, certFile)
	require.NoError(t, err)

	err = os.Rename(newKey, keyFile)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = os.Rename(certFile, newCert)
		_ = os.Rename(keyFile, newKey)

		_ = os.WriteFile(certFile, originalCert, 0600)
		_ = os.WriteFile(keyFile, originalKey, 0600)
	})
}
