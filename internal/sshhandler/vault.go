// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/hashicorp/vault/api/auth/aws"
	"github.com/hashicorp/vault/api/auth/gcp"

	vault "github.com/hashicorp/vault/api"

	gatewayconfig "k8sgateway/internal/config"
)

var errVaultAuthMethodNotConfigured = errors.New("no Vault auth method configured")

//nolint:ireturn
func newVaultAuthMethod(authConfig *gatewayconfig.SSHCAVaultAuthConfig) (vault.AuthMethod, error) {
	if authConfig.AppRole != nil {
		return newAppRoleAuthMethod(authConfig.AppRole)
	}

	if authConfig.GCP != nil {
		return newGCPAuthMethod(authConfig.GCP)
	}

	if authConfig.AWS != nil {
		return newAWSAuthMethod(authConfig.AWS)
	}

	return nil, errVaultAuthMethodNotConfigured
}

//nolint:ireturn
func newAppRoleAuthMethod(appRoleConfig *gatewayconfig.SSHCAVaultAppRoleConfig) (vault.AuthMethod, error) {
	secretID := &approle.SecretID{
		FromString: appRoleConfig.SecretID,
		FromFile:   appRoleConfig.SecretIDFile,
	}

	return approle.NewAppRoleAuth(
		appRoleConfig.RoleID,
		secretID,
		approle.WithMountPath(appRoleConfig.GetMount()),
	)
}

//nolint:ireturn
func newGCPAuthMethod(gcpConfig *gatewayconfig.SSHCAVaultGCPConfig) (vault.AuthMethod, error) {
	opts := []gcp.LoginOption{
		gcp.WithMountPath(gcpConfig.GetMount()),
	}

	// GCE is the default in the Vault GCP auth SDK
	if strings.EqualFold(gcpConfig.Type, "iam") {
		opts = append(opts, gcp.WithIAMAuth(gcpConfig.ServiceAccountEmail))
	}

	return gcp.NewGCPAuth(gcpConfig.Role, opts...)
}

//nolint:ireturn
func newAWSAuthMethod(awsConfig *gatewayconfig.SSHCAVaultAWSConfig) (vault.AuthMethod, error) {
	opts := []aws.LoginOption{
		aws.WithRole(awsConfig.Role),
		aws.WithMountPath(awsConfig.GetMount()),
	}

	if awsConfig.Region != "" {
		opts = append(opts, aws.WithRegion(awsConfig.Region))
	}

	if awsConfig.IAMServerIDHeader != "" {
		opts = append(opts, aws.WithIAMServerIDHeader(awsConfig.IAMServerIDHeader))
	}

	if strings.EqualFold(awsConfig.Type, "iam") {
		opts = append(opts, aws.WithIAMAuth())

		return aws.NewAWSAuth(opts...)
	}

	// EC2 auth
	opts = append(opts, aws.WithEC2Auth())

	if awsConfig.Nonce != "" {
		opts = append(opts, aws.WithNonce(awsConfig.Nonce))
	}

	// Apply signature type if specified. Default is pkcs7 in the Vault SDK.
	switch strings.ToLower(awsConfig.SignatureType) {
	case "identity":
		opts = append(opts, aws.WithIdentitySignature())
	case "rsa2048":
		opts = append(opts, aws.WithRSA2048Signature())
	case "pkcs7":
		opts = append(opts, aws.WithPKCS7Signature())
	default:
		// Use SDK default (pkcs7)
	}

	return aws.NewAWSAuth(opts...)
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
