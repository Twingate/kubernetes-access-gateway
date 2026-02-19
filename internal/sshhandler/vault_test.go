// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"testing"

	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/stretchr/testify/require"

	gatewayconfig "k8sgateway/internal/config"
)

func TestNewVaultAuthMethod_AppRole(t *testing.T) {
	cfg := &gatewayconfig.SSHCAVaultAuthConfig{
		AppRole: &gatewayconfig.SSHCAVaultAppRoleConfig{
			RoleID:       "role-id",
			SecretIDFile: "/path/to/secret-id",
			Mount:        "custom-approle",
		},
	}

	authMethod, err := newVaultAuthMethod(cfg)
	require.NoError(t, err)
	require.IsType(t, &approle.AppRoleAuth{}, authMethod)
}

func TestNewVaultAuthMethod_NoAuth(t *testing.T) {
	cfg := &gatewayconfig.SSHCAVaultAuthConfig{}

	authMethod, err := newVaultAuthMethod(cfg)
	require.ErrorIs(t, err, errVaultAuthMethodNotConfigured)
	require.Nil(t, authMethod)
}
