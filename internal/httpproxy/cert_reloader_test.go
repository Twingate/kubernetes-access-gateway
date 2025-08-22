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

	"k8sgateway/test/data"
)

const (
	certFile = "../../test/data/proxy/tls.crt"
	keyFile  = "../../test/data/proxy/tls.key"
)

func TestReloadWhenFileChanged(t *testing.T) {
	certReloader := newCertReloader(certFile, keyFile, zap.NewNop().Sugar())
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
	certReloader := newCertReloader(certFile, keyFile, zap.NewNop().Sugar())
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
}

func TestStop(t *testing.T) {
	certReloader := newCertReloader(certFile, keyFile, zap.NewNop().Sugar())
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

	assert.Equal(t, newCert.Certificate, expectedCert.Certificate)
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
