// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package fake

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

var errFailedToGetCaller = errors.New("failed to get caller")

func ReadECKey(filename string) (*ecdsa.PrivateKey, error) {
	privateKeyBytes, err := ReadFileFromProjectDirectory(filename)
	if err != nil {
		return nil, err
	}

	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		return nil, err
	}

	return x509.ParseECPrivateKey(privateKeyBlock.Bytes)
}

func ReadFileFromProjectDirectory(filename string) ([]byte, error) {
	_, b, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("reading file from project directory: %w", errFailedToGetCaller)
	}

	root := filepath.Join(filepath.Dir(b), "..", "..") // from ./test/fake to project directory
	path := filepath.Clean(filepath.Join(root, filename))

	return os.ReadFile(path)
}
