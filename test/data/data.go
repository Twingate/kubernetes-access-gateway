// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package data

import (
	_ "embed"
)

//go:embed client/key.pem
var ClientKey []byte

//go:embed controller/key.pem
var ControllerKey []byte

//go:embed proxy/tls.crt
var ProxyCert []byte
