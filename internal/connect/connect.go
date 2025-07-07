// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"

	"k8sgateway/internal/token"
)

// header that contains the auth token.
const AuthHeaderKey string = "Proxy-Authorization"

// header that contains the signature of the token for Proof-of-Possession.
const AuthSignatureHeaderKey string = "X-Token-Signature"

// header that contains the Connection ID.
const ConnIDHeaderKey string = "X-Connection-Id"

type Info struct {
	Claims *token.GATClaims
	ConnID string
}

type HTTPError struct {
	Err     error
	Code    int // HTTP status code
	Message string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

func (e *HTTPError) Unwrap() error {
	return e.Err
}

type Validator interface {
	ParseConnect(req *http.Request, ekm []byte) (connectInfo Info, err error)
}

type MessageValidator struct {
	TokenParser *token.Parser
}

func (v *MessageValidator) ParseConnect(req *http.Request, ekm []byte) (connectInfo Info, err error) {
	if req.Method != http.MethodConnect {
		// did not receive CONNECT, return 405 Method Not Allowed
		return Info{
				Claims: nil,
				ConnID: "",
			}, &HTTPError{
				Code:    http.StatusMethodNotAllowed,
				Message: "expected CONNECT request got " + req.Method,
				Err:     nil,
			}
	}

	connID := req.Header.Get(ConnIDHeaderKey)

	authHeader := req.Header.Get(AuthHeaderKey)

	bearerToken, tokenErr := token.ParseBearerToken(authHeader)
	if tokenErr != nil {
		// did not receive identity header in CONNECT, return 407 Proxy Authentication Required
		return Info{
				Claims: nil,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusProxyAuthRequired,
				Message: fmt.Sprintf("missing identity header in CONNECT %v", tokenErr),
				Err:     tokenErr,
			}
	}

	gatClaims := &token.GATClaims{}

	_, tokenErr = v.TokenParser.ParseWithClaims(bearerToken, gatClaims)
	if tokenErr != nil {
		return Info{
				Claims: nil,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusUnauthorized,
				Message: fmt.Sprintf("failed to parse token with error %v", tokenErr),
				Err:     tokenErr,
			}
	}

	// parse signature header for Proof-of-Possession
	signatureB64 := req.Header.Get(AuthSignatureHeaderKey)

	clientSig, tokenErr := base64.StdEncoding.DecodeString(signatureB64)
	if tokenErr != nil {
		return Info{
				Claims: gatClaims,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusUnauthorized,
				Message: fmt.Sprintf("failed to decode client signature with error %v", tokenErr),
				Err:     tokenErr,
			}
	}

	// verify signature
	hashed := sha256.Sum256(ekm)

	ok := ecdsa.VerifyASN1(&gatClaims.ClientPublicKey.PublicKey, hashed[:], clientSig)
	if !ok {
		return Info{
				Claims: gatClaims,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusUnauthorized,
				Message: "failed to verify signature",
				Err:     nil,
			}
	}

	// verify address in CONNECT with the GAT token
	address := req.RequestURI

	host, _, hostErr := net.SplitHostPort(address)
	if hostErr != nil {
		return Info{
				Claims: gatClaims,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusBadRequest,
				Message: fmt.Sprintf("failed to parse CONNECT destination: %v", hostErr),
				Err:     hostErr,
			}
	}

	if !strings.EqualFold(host, gatClaims.Resource.Address) {
		return Info{
				Claims: gatClaims,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusBadRequest,
				Message: fmt.Sprintf("failed to verify CONNECT destination: %s with token resource address %s", host, gatClaims.Resource.Address),
				Err:     nil,
			}
	}

	return Info{
		Claims: gatClaims,
		ConnID: connID,
	}, nil
}
