// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package fake

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
)

func ReadECKey(privateKeyBytes []byte) (*ecdsa.PrivateKey, error) {
	privateKeyBlock, _ := pem.Decode(privateKeyBytes)

	return x509.ParseECPrivateKey(privateKeyBlock.Bytes)
}
