// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package fake

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"

	"k8sgateway/test/data"
)

func ReadECKey(filename string) (*ecdsa.PrivateKey, error) {
	privateKeyBytes, err := data.Files.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		return nil, err
	}

	return x509.ParseECPrivateKey(privateKeyBlock.Bytes)
}
