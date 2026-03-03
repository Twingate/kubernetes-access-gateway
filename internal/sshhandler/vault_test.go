// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"testing"

	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/hashicorp/vault/api/auth/aws"
	"github.com/hashicorp/vault/api/auth/gcp"
	"github.com/stretchr/testify/require"

	gatewayconfig "k8sgateway/internal/config"
)

func TestNewVaultAuthMethod_AppRole(t *testing.T) {
	t.Run("with secretID", func(t *testing.T) {
		cfg := &gatewayconfig.SSHCAVaultAuthConfig{
			AppRole: &gatewayconfig.SSHCAVaultAppRoleConfig{
				RoleID:   "role-id",
				SecretID: "my-secret-id",
				Mount:    "custom-approle",
			},
		}

		authMethod, err := newVaultAuthMethod(cfg)
		require.NoError(t, err)
		require.IsType(t, &approle.AppRoleAuth{}, authMethod)
	})

	t.Run("with secretIDFile", func(t *testing.T) {
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
	})
}

func TestNewVaultAuthMethod_GCP(t *testing.T) {
	cfg := &gatewayconfig.SSHCAVaultAuthConfig{
		GCP: &gatewayconfig.SSHCAVaultGCPConfig{
			Mount:               "custom-gcp",
			Role:                "my-role",
			Type:                "iam",
			ServiceAccountEmail: "gateway-sa@project.iam.gserviceaccount.com",
		},
	}

	authMethod, err := newVaultAuthMethod(cfg)
	require.NoError(t, err)
	require.IsType(t, &gcp.GCPAuth{}, authMethod)
}

func TestNewVaultAuthMethod_AWS(t *testing.T) {
	t.Run("IAM", func(t *testing.T) {
		cfg := &gatewayconfig.SSHCAVaultAuthConfig{
			AWS: &gatewayconfig.SSHCAVaultAWSConfig{
				Mount:  "custom-aws",
				Role:   "my-role",
				Type:   "iam",
				Region: "us-west-2",
			},
		}

		authMethod, err := newVaultAuthMethod(cfg)
		require.NoError(t, err)
		require.IsType(t, &aws.AWSAuth{}, authMethod)
	})

	t.Run("EC2", func(t *testing.T) {
		cfg := &gatewayconfig.SSHCAVaultAuthConfig{
			AWS: &gatewayconfig.SSHCAVaultAWSConfig{
				Mount:         "custom-aws",
				Role:          "my-role",
				Type:          "ec2",
				SignatureType: "identity",
				Nonce:         "my-nonce",
			},
		}

		authMethod, err := newVaultAuthMethod(cfg)
		require.NoError(t, err)
		require.IsType(t, &aws.AWSAuth{}, authMethod)
	})
}

func TestNewVaultAuthMethod_NoAuth(t *testing.T) {
	cfg := &gatewayconfig.SSHCAVaultAuthConfig{}

	authMethod, err := newVaultAuthMethod(cfg)
	require.ErrorIs(t, err, errVaultAuthMethodNotConfigured)
	require.Nil(t, authMethod)
}
