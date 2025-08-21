// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"crypto/tls"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const (
	certFile = "../../test/data/proxy/tls1.crt"
	keyFile  = "../../test/data/proxy/tls1.key"
)

func TestReloadWhenFileChanged(t *testing.T) {
	originalCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)

	certReloader := newCertReloader(certFile, keyFile, zap.NewNop().Sugar())
	certReloader.watch()

	updateCertificate(t, "../../test/data/proxy/tls.crt", "../../test/data/proxy/tls.key")

	time.Sleep(200 * time.Millisecond)

	hello := &tls.ClientHelloInfo{}

	newCert, err := certReloader.getCertificate(hello)
	require.NoError(t, err)

	isEqual := reflect.DeepEqual(newCert.Certificate, originalCert.Certificate)
	assert.False(t, isEqual)
}

func TestDontReload_WhenInvalidKeyPair(t *testing.T) {
	originalCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)

	certReloader := newCertReloader(certFile, keyFile, zap.NewNop().Sugar())
	certReloader.watch()

	// Invalid key pair
	updateCertificate(t, "../../test/data/proxy/tls.crt", "../../test/data/proxy/tls1.key")

	time.Sleep(200 * time.Millisecond)

	hello := &tls.ClientHelloInfo{}

	newCert, err := certReloader.getCertificate(hello)
	require.NoError(t, err)

	// Ensure certificate is unchanged
	isEqual := reflect.DeepEqual(newCert.Certificate, originalCert.Certificate)
	assert.True(t, isEqual)
}

func TestGetCertificate(t *testing.T) {
	certReloader := newCertReloader(certFile, keyFile, zap.NewNop().Sugar())
	certReloader.watch()

	hello := &tls.ClientHelloInfo{}

	cert, err := certReloader.getCertificate(hello)
	require.NoError(t, err)

	expectedCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)

	isEqual := reflect.DeepEqual(cert.Certificate, expectedCert.Certificate)
	assert.True(t, isEqual)
}

func TestStop(t *testing.T) {
	originalCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)

	certReloader := newCertReloader(certFile, keyFile, zap.NewNop().Sugar())
	certReloader.watch()

	certReloader.stop()

	updateCertificate(t, "../../test/data/proxy/tls.crt", "../../test/data/proxy/tls.key")

	time.Sleep(200 * time.Millisecond)

	hello := &tls.ClientHelloInfo{}

	newCert, err := certReloader.getCertificate(hello)
	require.NoError(t, err)

	isEqual := reflect.DeepEqual(newCert.Certificate, originalCert.Certificate)
	assert.True(t, isEqual)
}

func updateCertificate(t *testing.T, cert, key string) {
	t.Helper()

	origCert, err := os.ReadFile(certFile)
	require.NoError(t, err)
	certInfo, err := os.Stat(certFile)
	require.NoError(t, err)

	origKey, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	keyInfo, err := os.Stat(keyFile)
	require.NoError(t, err)

	certSource, _ := os.Open(cert) // #nosec G304 -- we're reading our own cert
	defer certSource.Close()

	certDest, _ := os.Create(certFile)
	defer certDest.Close()

	_, err = io.Copy(certDest, certSource)
	require.NoError(t, err)

	keySource, _ := os.Open(key) // #nosec G304 -- we're reading our own key
	defer keySource.Close()

	keyDest, _ := os.Create(keyFile)
	defer keyDest.Close()

	_, err = io.Copy(keyDest, keySource)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = os.WriteFile(certFile, origCert, certInfo.Mode())
		_ = os.WriteFile(keyFile, origKey, keyInfo.Mode())
	})
}
