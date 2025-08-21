package data

import (
	"embed"
)

//go:embed client/key.pem controller/key.pem proxy/tls.crt
var Files embed.FS
