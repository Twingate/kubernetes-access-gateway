package connect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
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
	signature, _ := ecdsa.SignASN1(rand.Reader, c.privateKey, hash[:])

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

	parser, err := token.NewParser(token.ParserConfig{
		Network: "acme",
		Host:    "twingate.com",
		Keyfunc: func(_token *jwt.Token) (any, error) {
			return &privateKey.PublicKey, nil
		},
	})
	require.NoError(t, err)

	gatToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	gatToken.Header["typ"] = "GAT"
	tokenStr, err := gatToken.SignedString(privateKey)
	require.NoError(t, err)

	return parser, tokenStr
}

func TestConnectValidator_ParseConnect(t *testing.T) {
	log.InitializeLogger("gateway", false)

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

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		require.NoError(t, err)
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Non-CONNECT method", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request with GET method instead of CONNECT
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError
		if !errors.As(err, &httpErr) {
			t.Fatalf("expected error of type *HTTPError, but got %T (%v)", err, err)
		}

		require.NoError(t, httpErr.Err)
		require.Error(t, httpErr)
		assert.Equal(t, http.StatusMethodNotAllowed, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "expected CONNECT request")
		assert.Nil(t, connectInfo.Claims)
		assert.Empty(t, connectInfo.ConnID)
	})

	t.Run("Missing auth header", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request without auth header
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError
		if !errors.As(err, &httpErr) {
			t.Fatalf("expected error of type *HTTPError, but got %T (%v)", err, err)
		}

		require.Error(t, httpErr.Err)
		require.Error(t, httpErr)
		assert.Equal(t, http.StatusProxyAuthRequired, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "missing identity header")
		assert.Nil(t, connectInfo.Claims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
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

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError
		if !errors.As(err, &httpErr) {
			t.Fatalf("expected error of type *HTTPError, but got %T (%v)", err, err)
		}

		require.Error(t, httpErr.Err)
		require.Error(t, httpErr)
		assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to parse token")
		assert.Nil(t, connectInfo.Claims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Invalid signature format", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request with invalid signature in header
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)
		req.Header.Set(AuthSignatureHeaderKey, "invalid-signature")
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError
		if !errors.As(err, &httpErr) {
			t.Fatalf("expected error of type *HTTPError, but got %T (%v)", err, err)
		}

		require.Error(t, httpErr.Err)
		require.Error(t, httpErr)
		assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to decode client signature")
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Missing signature header", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request without signature header
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError
		if !errors.As(err, &httpErr) {
			t.Fatalf("expected error of type *HTTPError, but got %T (%v)", err, err)
		}

		require.NoError(t, httpErr.Err)
		require.Error(t, httpErr)
		assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to verify signature")
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Invalid ASN.1 format", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request with signature with valid base64 but invalid ASN.1
		invalidSignature := base64.StdEncoding.EncodeToString([]byte("not valid ASN.1 format"))
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)
		req.Header.Set(AuthSignatureHeaderKey, invalidSignature)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError
		if !errors.As(err, &httpErr) {
			t.Fatalf("expected error of type *HTTPError, but got %T (%v)", err, err)
		}

		require.NoError(t, httpErr.Err)
		require.Error(t, httpErr)
		assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to verify signature")
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Signature verification failure", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request with mismatched signature
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)

		signature := c.sign("different-token")
		req.Header.Set(AuthSignatureHeaderKey, signature)

		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError
		if !errors.As(err, &httpErr) {
			t.Fatalf("expected error of type *HTTPError, but got %T (%v)", err, err)
		}

		require.NoError(t, httpErr.Err)
		require.Error(t, httpErr)
		assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to verify signature")
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Invalid destination (not in token)", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request
		req := httptest.NewRequest(http.MethodConnect, "website.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)

		signature := c.sign(sigData)
		req.Header.Set(AuthSignatureHeaderKey, signature)

		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError
		if !errors.As(err, &httpErr) {
			t.Fatalf("expected error of type *HTTPError, but got %T (%v)", err, err)
		}

		require.NoError(t, httpErr.Err)
		require.Error(t, httpErr)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to verify CONNECT destination")
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Invalid destination, missing", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request
		req := httptest.NewRequest(http.MethodConnect, "", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)

		signature := c.sign(sigData)
		req.Header.Set(AuthSignatureHeaderKey, signature)

		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError
		if !errors.As(err, &httpErr) {
			t.Fatalf("expected error of type *HTTPError, but got %T (%v)", err, err)
		}

		require.Error(t, httpErr.Err)
		require.Error(t, httpErr)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to parse CONNECT destination")
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})
}

func TestHTTPError_Error(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		message string
		want    string
	}{
		{
			name:    "Not Found",
			code:    404,
			message: "Not Found",
			want:    "404: Not Found",
		},
		{
			name:    "Internal Server Error",
			code:    500,
			message: "Internal Server Error",
			want:    "500: Internal Server Error",
		},
		{
			name:    "Bad Request",
			code:    400,
			message: "Bad Request",
			want:    "400: Bad Request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &HTTPError{
				Code:    tt.code,
				Message: tt.message,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("HTTPError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}
