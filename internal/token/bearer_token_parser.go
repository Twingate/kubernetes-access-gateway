// Package token manages the parsing of bearer tokens
package token

import (
	"errors"
	"fmt"
	"strings"
)

var errTokenParsingFailed = errors.New("failed to parse bearer token")

func ParseBearerToken(authHeader string) (token string, err error) {
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("%w : %s", errTokenParsingFailed, authHeader)
	}

	return parts[1], err
}
