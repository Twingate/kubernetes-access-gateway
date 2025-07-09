// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package fake

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
)

func ReadECKey(filename string) (*ecdsa.PrivateKey, error) {
	filename = filepath.Clean(filename)

	privateKeyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		return nil, err
	}

	return x509.ParseECPrivateKey(privateKeyBlock.Bytes)
}
