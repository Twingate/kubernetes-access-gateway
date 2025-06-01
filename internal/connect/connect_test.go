package connect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8sgateway/internal/log"
	"k8sgateway/internal/token"
)

type client struct {
	privateKey *ecdsa.PrivateKey
}

func (c client) getPublicKey() token.PublicKey {
	return token.PublicKey{PublicKey: c.privateKey.PublicKey}
}

func (c client) sign(t string) string {
	hash := sha256.Sum256([]byte(t))
	r, s, _ := ecdsa.Sign(rand.Reader, c.privateKey, hash[:])

	signature, _ := asn1.Marshal(ECDSASignature{R: r, S: s})

	return base64.StdEncoding.EncodeToString(signature)
}

func newClient() client {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	return client{privateKey}
}

func newGATTokenClaims(clientPublicKey token.PublicKey) token.GATClaims {
	return token.GATClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "twingate",
			Audience:  jwt.ClaimStrings{"acme"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Version:         "1",
		RenewAt:         jwt.NewNumericDate(time.Now().Add(time.Minute)),
		ClientPublicKey: clientPublicKey,
		User: token.User{
			ID:       "user-1",
			Username: "user@acme.com",
			Groups:   []string{"Everyone", "Engineering"},
		},
		Device: token.Device{
			ID: "device-1",
		},
		Resource: token.Resource{ID: "resource-1", Address: "example.com"},
	}
}

func createParserAndGATToken(t *testing.T, claims token.GATClaims) (*token.Parser, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	parser := token.NewParser(
		"acme",
		"twingate.com",
		func(_token *jwt.Token) (any, error) {
			return &privateKey.PublicKey, nil
		},
	)

	gatToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	gatToken.Header["typ"] = "GAT"
	tokenStr, err := gatToken.SignedString(privateKey)
	require.NoError(t, err)

	return parser, tokenStr
}

func TestConnectValidator_ParseConnect(t *testing.T) {
	log.InitializeLogger("k8sproxytest", false)

	c := newClient()
	gatClaims := newGATTokenClaims(c.getPublicKey())
	parser, signedToken := createParserAndGATToken(t, gatClaims)

	sigData := "test-signature"

	t.Run("Successful authentication", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		signature := c.sign(sigData)
		// create request
		req := httptest.NewRequest(http.MethodConnect, "Example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)
		req.Header.Set(AuthSignatureHeaderKey, signature)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		parsedClaims, connID, response, err := validator.ParseConnect(req, []byte(sigData))

		require.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 200 Connection Established\r\n\r\n", response)
		assert.Equal(t, *parsedClaims, gatClaims)
		assert.Equal(t, "conn-id", connID)
	})

	t.Run("Non-CONNECT method", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request with GET method instead of CONNECT
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)

		connectInfo, _, response, err := validator.ParseConnect(req, []byte(sigData))

		require.Error(t, err)
		assert.Equal(t, "HTTP/1.1 405 Method Not Allowed\r\n\r\n", response)
		assert.Nil(t, connectInfo)
		assert.Contains(t, err.Error(), "expected CONNECT request")
	})

	t.Run("Missing auth header", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request without auth header
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, connID, response, err := validator.ParseConnect(req, []byte(sigData))

		require.Error(t, err)
		assert.Equal(t, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", response)
		assert.Nil(t, connectInfo)
		assert.Contains(t, err.Error(), "missing identity header")
		assert.Equal(t, "conn-id", connID)
	})

	t.Run("Invalid token", func(t *testing.T) {
		parser, invalidToken := createParserAndGATToken(
			t,
			token.GATClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				},
				ClientPublicKey: c.getPublicKey(),
			},
		)
		validator := &MessageValidator{TokenParser: parser}

		// create request with invalid token
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+invalidToken)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, connID, response, err := validator.ParseConnect(req, []byte(sigData))

		require.Error(t, err)
		assert.Equal(t, "HTTP/1.1 401 Unauthorized\r\n\r\n", response)
		assert.Nil(t, connectInfo)
		assert.Contains(t, err.Error(), "failed to parse token")
		assert.Equal(t, "conn-id", connID)
	})

	t.Run("Invalid signature format", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request with invalid signature in header
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)
		req.Header.Set(AuthSignatureHeaderKey, "invalid-signature")
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, connID, response, err := validator.ParseConnect(req, []byte(sigData))

		require.Error(t, err)
		assert.Equal(t, "HTTP/1.1 401 Unauthorized\r\n\r\n", response)
		assert.Equal(t, *connectInfo, gatClaims)
		assert.Contains(t, err.Error(), "failed to decode client signature")
		assert.Equal(t, "conn-id", connID)
	})

	t.Run("Missing signature header", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request without signature header
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, connID, response, err := validator.ParseConnect(req, []byte(sigData))

		require.Error(t, err)
		assert.Equal(t, "HTTP/1.1 401 Unauthorized\r\n\r\n", response)
		assert.Equal(t, *connectInfo, gatClaims)
		assert.Contains(t, err.Error(), "failed to verify signature")
		assert.Equal(t, "conn-id", connID)
	})

	t.Run("Invalid ASN.1 format", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request with signature with valid base64 but invalid ASN.1
		invalidSignature := base64.StdEncoding.EncodeToString([]byte("not valid ASN.1 format"))
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)
		req.Header.Set(AuthSignatureHeaderKey, invalidSignature)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, connID, response, err := validator.ParseConnect(req, []byte(sigData))

		require.Error(t, err)
		assert.Equal(t, "HTTP/1.1 401 Unauthorized\r\n\r\n", response)
		assert.Equal(t, *connectInfo, gatClaims)
		assert.Contains(t, err.Error(), "failed to verify signature")
		assert.Equal(t, "conn-id", connID)
	})

	t.Run("Signature verification failure", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request with mismatched signature
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)

		signature := c.sign("different-token")
		req.Header.Set(AuthSignatureHeaderKey, signature)

		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, connID, response, err := validator.ParseConnect(req, []byte(sigData))

		require.Error(t, err)
		assert.Equal(t, "HTTP/1.1 401 Unauthorized\r\n\r\n", response)
		assert.Equal(t, *connectInfo, gatClaims)
		assert.Contains(t, err.Error(), "failed to verify signature")
		assert.Equal(t, "conn-id", connID)
	})

	t.Run("Invalid destination (not in token)", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request
		req := httptest.NewRequest(http.MethodConnect, "website.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)

		signature := c.sign(sigData)
		req.Header.Set(AuthSignatureHeaderKey, signature)

		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, connID, response, err := validator.ParseConnect(req, []byte(sigData))

		require.Error(t, err)
		assert.Equal(t, "HTTP/1.1 401 Unauthorized\r\n\r\n", response)
		assert.Equal(t, *connectInfo, gatClaims)
		assert.Contains(t, err.Error(), "failed to verify CONNECT destination")
		assert.Equal(t, "conn-id", connID)
	})

	t.Run("Invalid destination, missing", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request
		req := httptest.NewRequest(http.MethodConnect, "", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)

		signature := c.sign(sigData)
		req.Header.Set(AuthSignatureHeaderKey, signature)

		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, connID, response, err := validator.ParseConnect(req, []byte(sigData))

		require.Error(t, err)
		assert.Equal(t, "HTTP/1.1 401 Unauthorized\r\n\r\n", response)
		assert.Equal(t, *connectInfo, gatClaims)
		assert.Contains(t, err.Error(), "failed to parse CONNECT destination")
		assert.Equal(t, "conn-id", connID)
	})
}
