// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

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

type ParserConfig struct {
	// Twingate network ID
	Network string
	// Twingate service domain
	Host string
	// URL which issues JWKs to verify token. Default to `https://<Network>.<Host>`
	URL string
	// Keyfunc to verify token. Default to using remote JWKs
	Keyfunc jwt.Keyfunc
}

type Parser struct {
	parser *jwt.Parser
	config ParserConfig
}

func NewParser(config ParserConfig) (*Parser, error) {
	if config.Keyfunc == nil {
		if config.URL == "" {
			config.URL = fmt.Sprintf("https://%s.%s", config.Network, config.Host)
		}

		jwkURL := config.URL + "/api/v1/jwk/ec"

		jwks, err := keyfunc.NewDefault([]string{jwkURL})
		if err != nil {
			return nil, fmt.Errorf("failed to create JWKS store: %w", err)
		}

		config.Keyfunc = jwks.Keyfunc
	}

	return &Parser{
		parser: jwt.NewParser(
			jwt.WithValidMethods(allowedSigningMethods),
			jwt.WithIssuer(allowedIssuerByHost[config.Host]),
			jwt.WithAudience(config.Network),
			jwt.WithIssuedAt(),
			jwt.WithExpirationRequired(),
		),
		config: config,
	}, nil
}

func (p *Parser) ParseWithClaims(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	token, err := p.parser.ParseWithClaims(tokenString, claims, p.config.Keyfunc)
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
