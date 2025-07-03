// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0
//

package token

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseBearerTokenValid(t *testing.T) {
	authHeader := "Bearer token"
	actualToken, err := ParseBearerToken(authHeader)
	assert.Equal(t, "token", actualToken)
	assert.NoError(t, err, "expected success, received error %v", err)
}

func TestParseBearerTokenCasing(t *testing.T) {
	testToken := "BEARER TOKEN"
	token, err := ParseBearerToken(testToken)

	assert.Equal(t, "TOKEN", token)
	assert.NoError(t, err, "expected success, received error %v", err)
}

func TestParseBearerTokenInvalid(t *testing.T) {
	authHeader := "BearerTOKEN"
	token, err := ParseBearerToken(authHeader)

	assert.Empty(t, token)
	assert.Error(t, err, "expected error, received nil")
}

func TestParseBearerTokenEmptyHeader(t *testing.T) {
	token, err := ParseBearerToken("")

	assert.Empty(t, token)
	assert.Error(t, err, "expected error, received nil")
}

func TestParseBearerTokenWrongAuthScheme(t *testing.T) {
	token, err := ParseBearerToken("Basic token")

	assert.Empty(t, token)
	assert.Error(t, err, "expected error, received nil")
}
