package token

import (
	"errors"
	"fmt"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

var errInvalidTokenType = errors.New("token type is invalid")

var allowedSigningMethods = []string{jwt.SigningMethodES256.Alg()}

var allowedIssuerByHost = map[string]string{
	"test.local":    "twingate-local",
	"dev.opstg.com": "twingate-dev",
	"stg.opstg.com": "twingate-stg",
	"twingate.com":  "twingate",
}

type ClaimsWithHeaderType interface {
	getHeaderType() string
}

type Parser struct {
	parser  *jwt.Parser
	keyfunc jwt.Keyfunc
}

func NewParserWithRemotesJWKS(network, host, overrideURL string) (*Parser, error) {
	var url = fmt.Sprintf("https://%s.%s", network, host)
	if overrideURL != "" {
		url = overrideURL
	}

	jwkURL := url + "/api/v1/jwk/ec"

	jwks, err := keyfunc.NewDefault([]string{jwkURL})
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS store: %w", err)
	}

	return NewParser(network, host, jwks.Keyfunc), nil
}

func NewParser(network, host string, keyfunc jwt.Keyfunc) *Parser {
	return &Parser{
		parser: jwt.NewParser(
			jwt.WithValidMethods(allowedSigningMethods),
			jwt.WithIssuer(allowedIssuerByHost[host]),
			jwt.WithAudience(network),
			jwt.WithIssuedAt(),
			jwt.WithExpirationRequired(),
		),
		keyfunc: keyfunc,
	}
}

func (p *Parser) ParseWithClaims(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	token, err := p.parser.ParseWithClaims(tokenString, claims, p.keyfunc)
	if err != nil {
		return nil, err
	}

	if claim, ok := claims.(ClaimsWithHeaderType); ok {
		if headerTyp, ok := token.Header["typ"].(string); !ok || headerTyp != claim.getHeaderType() {
			return nil, errInvalidTokenType
		}
	}

	return token, nil
}
