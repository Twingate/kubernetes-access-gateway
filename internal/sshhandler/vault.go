// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api/auth/approle"
	"go.uber.org/zap"

	vault "github.com/hashicorp/vault/api"

	gatewayconfig "k8sgateway/internal/config"
)

var errVaultAuthMethodNotConfigured = errors.New("no Vault auth method configured")

const (
	loginRetryInterval = 1 * time.Minute
)

// VaultClient manages a Vault API client and handles automatic token renewal.
type VaultClient struct {
	client     *vault.Client
	authMethod vault.AuthMethod
	logger     *zap.Logger
}

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

	return nil, errVaultAuthMethodNotConfigured
}

func NewVaultClient(vaultConfig *gatewayconfig.SSHCAVaultConfig, logger *zap.Logger) (*VaultClient, error) {
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

	vc := &VaultClient{client: client, logger: logger}

	client.SetNamespace(vaultConfig.Namespace)

	if vaultConfig.Auth.Token != "" {
		client.SetToken(vaultConfig.Auth.Token)

		return vc, nil
	}

	authMethod, err := newVaultAuthMethod(&vaultConfig.Auth)
	// No auth method configured — Vault SDK falls back to VAULT_TOKEN environment variable
	if errors.Is(err, errVaultAuthMethodNotConfigured) {
		return vc, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create Vault auth method: %w", err)
	}

	vc.authMethod = authMethod

	return vc, nil
}

// RunTokenRenewalLoop runs the token lifecycle watcher and login loop until context is canceled.
// Whenever the token expires or renewal fails, it re-logins using the configured auth method and
// start the token lifecycle watcher again with the new token. If login fails, it retries after a delay.
func (vc *VaultClient) RunTokenRenewalLoop(ctx context.Context, secret *vault.Secret) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err := vc.watchTokenLifecycle(ctx, secret); err != nil {
				vc.logger.Error("Failed to watch Vault token lifecycle, will retry later", zap.Error(err))
			}

			secret = vc.loginWithRetry(ctx)
		}
	}
}

func (vc *VaultClient) watchTokenLifecycle(ctx context.Context, secret *vault.Secret) error {
	watcher, err := vc.client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret: secret,
	})
	if err != nil {
		return fmt.Errorf("failed to create Vault token lifetime watcher: %w", err)
	}

	vc.logger.Info("Start Vault token lifetime watcher")

	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-watcher.DoneCh():
			if err != nil {
				vc.logger.Error("Failed to renew Vault token, re-attempting login", zap.Error(err))

				return nil
			}

			vc.logger.Info("Vault token can no longer be renewed, re-attempting login")

			return nil
		case info := <-watcher.RenewCh():
			vc.logger.Info("Successfully renewed Vault token", zap.Time("renewed_at", info.RenewedAt))
		}
	}
}

func (vc *VaultClient) loginWithRetry(ctx context.Context) *vault.Secret {
	for {
		secret, err := vc.client.Auth().Login(ctx, vc.authMethod)
		if err == nil {
			vc.logger.Info("Successfully login to Vault")

			return secret
		}

		vc.logger.Error("Failed to login to Vault, will retry later", zap.Error(err))

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(loginRetryInterval):
		}
	}
}
