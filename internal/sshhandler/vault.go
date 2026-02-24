// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/hashicorp/vault/api/auth/gcp"

	vault "github.com/hashicorp/vault/api"

	gatewayconfig "k8sgateway/internal/config"
)

var errVaultAuthMethodNotConfigured = errors.New("no Vault auth method configured")

//nolint:ireturn
func newVaultAuthMethod(authConfig *gatewayconfig.SSHCAVaultAuthConfig) (vault.AuthMethod, error) {
	if authConfig.AppRole != nil {
		secretID := &approle.SecretID{
			FromString: authConfig.AppRole.SecretID,
			FromFile:   authConfig.AppRole.SecretIDFile,
		}

		return approle.NewAppRoleAuth(
			authConfig.AppRole.RoleID,
			secretID,
			approle.WithMountPath(authConfig.AppRole.GetMount()),
		)
	}

	if authConfig.GCP != nil {
		// Default auth method type is GCE
		opts := []gcp.LoginOption{
			gcp.WithMountPath(authConfig.GCP.GetMount()),
		}

		if strings.EqualFold(authConfig.GCP.Type, "iam") {
			opts = append(opts, gcp.WithIAMAuth(authConfig.GCP.ServiceAccountEmail))
		}

		return gcp.NewGCPAuth(authConfig.GCP.Role, opts...)
	}

	return nil, errVaultAuthMethodNotConfigured
}

// newVaultClient returns an authenticated Vault client.
func newVaultClient(vaultConfig *gatewayconfig.SSHCAVaultConfig) (*vault.Client, error) {
	config := vault.DefaultConfig()
	config.Address = vaultConfig.Address

	if vaultConfig.CABundleFile != "" {
		if err := config.ConfigureTLS(&vault.TLSConfig{
			CACert: vaultConfig.CABundleFile,
		}); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
	}

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	client.SetNamespace(vaultConfig.Namespace)

	if vaultConfig.Auth.Token != "" {
		client.SetToken(vaultConfig.Auth.Token)

		return client, nil
	}

	authMethod, err := newVaultAuthMethod(&vaultConfig.Auth)
	// No auth method configured — Vault SDK falls back to VAULT_TOKEN environment variable
	if errors.Is(err, errVaultAuthMethodNotConfigured) {
		return client, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create Vault auth method: %w", err)
	}

	if _, err := client.Auth().Login(context.Background(), authMethod); err != nil {
		return nil, fmt.Errorf("failed to authenticate to Vault: %w", err)
	}

	return client, nil
}
