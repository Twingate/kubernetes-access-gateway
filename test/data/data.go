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

//go:embed proxy/tls.key
var ProxyKey []byte

//go:embed proxy/tls1.crt
var ProxyCert1 []byte

//go:embed proxy/tls1.key
var ProxyKey1 []byte

//go:embed api_server/tls.crt
var ServerCert []byte

//go:embed api_server/tls.key
var ServerKey []byte
