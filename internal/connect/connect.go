package connect

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"

	"k8sgateway/internal/token"
)

var (
	errExpectedConnectRequest      = errors.New("expected CONNECT request")
	errSignatureVerificationFailed = errors.New("failed to verify signature")
)

const unauthorizedResponse = "HTTP/1.1 401 Unauthorized\r\n\r\n"

type ECDSASignature struct {
	R, S *big.Int
}

// header that contains the auth token.
const AuthHeaderKey string = "Proxy-Authorization"

// header that contains the signature of the token for Proof-of-Possession.
const AuthSignatureHeaderKey string = "X-Token-Signature"

// header that contains the Connection ID.
const ConnIDHeaderKey string = "X-Connection-Id"

type Validator interface {
	ParseConnect(req *http.Request, ekm []byte) (claims *token.GATClaims, connID string, response string, err error)
}

type MessageValidator struct {
	TokenParser *token.Parser
}

func (v *MessageValidator) ParseConnect(req *http.Request, ekm []byte) (claims *token.GATClaims, connID string, response string, err error) {
	if req.Method != http.MethodConnect {
		// did not receive CONNECT, respond with 405 Method Not Allowed
		response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n"

		return nil, "", response, fmt.Errorf("%w, got %s", errExpectedConnectRequest, req.Method)
	}

	connID = req.Header.Get(ConnIDHeaderKey)

	authHeader := req.Header.Get(AuthHeaderKey)

	bearerToken, err := token.ParseBearerToken(authHeader)
	if err != nil {
		// did not receive identity header in CONNECT, respond with 407 Proxy Authentication Required and
		// close the connection
		response = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"

		return nil, connID, response, fmt.Errorf("missing identity header in CONNECT %w", err)
	}

	gatClaims := &token.GATClaims{}

	_, err = v.TokenParser.ParseWithClaims(bearerToken, gatClaims)
	if err != nil {
		response = unauthorizedResponse

		return nil, connID, response, fmt.Errorf("failed to parse token with error %w", err)
	}

	// parse signature header for Proof-of-Possession
	signatureB64 := req.Header.Get(AuthSignatureHeaderKey)

	clientSig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		response = unauthorizedResponse

		return gatClaims, connID, response, fmt.Errorf("failed to decode client signature with error %w", err)
	}

	// verify signature
	hashed := sha256.Sum256(ekm)

	ok := ecdsa.VerifyASN1(&gatClaims.ClientPublicKey.PublicKey, hashed[:], clientSig)
	if !ok {
		response = unauthorizedResponse

		return gatClaims, connID, response, errSignatureVerificationFailed
	}

	// verify address in CONNECT with the GAT token
	address := req.RequestURI

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		response = unauthorizedResponse

		return gatClaims, connID, response, fmt.Errorf("failed to parse CONNECT destination: %w", err)
	}

	if !strings.EqualFold(host, gatClaims.Resource.Address) {
		response = unauthorizedResponse

		return gatClaims, connID, response, fmt.Errorf("failed to verify CONNECT destination: %s(err: %w) with token resource address %s", host, err, gatClaims.Resource.Address)
	}

	response = "HTTP/1.1 200 Connection Established\r\n\r\n"

	return gatClaims, connID, response, nil
}
