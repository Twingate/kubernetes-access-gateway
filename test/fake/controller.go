package fake

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"

	"k8sgateway/internal/token"
)

const keyID = "1"
const issuer = "twingate-local"

// NewController creates an HTTP server that simulates a Twingate controller.
//
// It has two endpoints:
// - /api/v1/jwk/ec: Returns the JWK Set that is used to verify GAT tokens.
// - /api/v1/gat: Returns a GAT token for a client.
func NewController(network string) *httptest.Server {
	logger := log.New(os.Stdout, "fake-controller:", log.LstdFlags)

	controllerKey, _ := ReadECKey("../data/controller/key.pem")

	jwkSetJSON, err := createJWKSet(controllerKey)
	if err != nil {
		logger.Printf("Failed to create JWK Set: %s", err)

		return nil
	}

	// TODO: client should send this key as well as other client's info...
	clientKey, _ := ReadECKey("../data/client/key.pem")

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/jwk/ec", func(writer http.ResponseWriter, _request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")

		_, err := writer.Write(jwkSetJSON)
		if err != nil {
			logger.Printf("Failed to respond with JWK Set JSON: %s", err)

			return
		}

		logger.Println("JWK returned")
	})
	mux.HandleFunc("/api/v1/gat", func(writer http.ResponseWriter, _request *http.Request) {
		claims := token.GATClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Audience:  jwt.ClaimStrings([]string{network}),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Version:         "1",
			RenewAt:         jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ClientPublicKey: token.PublicKey{PublicKey: clientKey.PublicKey},
			User: token.User{
				ID:       "user-1",
				Username: "alex@acme.com",
				Groups:   []string{"OnCall", "Product Engineer"},
			},
			Device: token.Device{
				ID: "device-1",
			},
			Resource: token.Resource{
				ID:      "resource-1",
				Address: "127.0.0.1",
			},
		}

		token := &jwt.Token{
			Header: map[string]any{
				"typ": "GAT",
				"alg": jwt.SigningMethodES256.Alg(),
				"kid": keyID,
			},
			Claims: claims,
			Method: jwt.SigningMethodES256,
		}

		tokenString, err := token.SignedString(controllerKey)
		if err != nil {
			logger.Printf("Failed to sign JWT. %s", err)

			return
		}

		_, err = writer.Write([]byte(tokenString))
		if err != nil {
			logger.Printf("Failed to respond with JWT: %s", err)

			return
		}

		logger.Println("JWT generated.")
	})

	return httptest.NewServer(mux)
}

func createJWKSet(controllerKey *ecdsa.PrivateKey) (json.RawMessage, error) {
	jwkSet := jwkset.NewMemoryStorage()

	metadata := jwkset.JWKMetadataOptions{
		KID: keyID,
	}
	options := jwkset.JWKOptions{
		Metadata: metadata,
	}

	jwk, err := jwkset.NewJWKFromKey(controllerKey, options)
	if err != nil {
		return nil, err
	}

	err = jwkSet.KeyWrite(context.Background(), jwk)
	if err != nil {
		return nil, err
	}

	publicKeyJSON, err := jwkSet.JSONPublic(context.Background())
	if err != nil {
		return nil, err
	}

	return publicKeyJSON, nil
}
