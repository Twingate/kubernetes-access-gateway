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
	originalCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)

	certReloader := newCertReloader(certFile, keyFile, zap.NewNop().Sugar())
	certReloader.watch()

	updateCertFiles(t, data.ProxyCert1, data.ProxyKey1)

	time.Sleep(5 * time.Millisecond)

	hello := &tls.ClientHelloInfo{}

	newCert, err := certReloader.getCertificate(hello)
	require.NoError(t, err)

	assert.NotEqual(t, newCert.Certificate, originalCert.Certificate)
}

func TestDontReloadWhenInvalidKeyPair(t *testing.T) {
	originalCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)

	certReloader := newCertReloader(certFile, keyFile, zap.NewNop().Sugar())
	certReloader.watch()

	// Invalid key pair
	updateCertFiles(t, data.ProxyCert1, data.ProxyKey)

	hello := &tls.ClientHelloInfo{}

	time.Sleep(5 * time.Millisecond)

	newCert, err := certReloader.getCertificate(hello)
	require.NoError(t, err)

	// Ensure certificate is unchanged
	assert.Equal(t, newCert.Certificate, originalCert.Certificate)
}

func TestStop(t *testing.T) {
	originalCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)

	certReloader := newCertReloader(certFile, keyFile, zap.NewNop().Sugar())
	certReloader.watch()

	certReloader.stop()

	updateCertFiles(t, data.ProxyCert1, data.ProxyKey1)

	time.Sleep(5 * time.Millisecond)

	hello := &tls.ClientHelloInfo{}

	newCert, err := certReloader.getCertificate(hello)
	require.NoError(t, err)

	assert.Equal(t, newCert.Certificate, originalCert.Certificate)
}

func updateCertFiles(t *testing.T, newCert, newKey []byte) {
	t.Helper()

	originalCert := data.ProxyCert
	originalKey := data.ProxyKey

	err := os.WriteFile(certFile, newCert, 0644)
	require.NoError(t, err)

	err = os.WriteFile(keyFile, newKey, 0644)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = os.WriteFile(certFile, originalCert, 0644)
		_ = os.WriteFile(keyFile, originalKey, 0644)
	})
}
