package testutil

import (
	"fmt"

	"k8sgateway/internal/token"
	"k8sgateway/test/fake"
)

// User represents a user, its Kubectl instance and its fake Client.
type User struct {
	token.User
	Kubectl *Kubectl

	client *fake.Client
}

func NewUser(user *token.User, gatewayPort int, kindURL, controllerURL string) (*User, error) {
	client := fake.NewClient(
		user,
		fmt.Sprintf("127.0.0.1:%d", gatewayPort),
		controllerURL,
		kindURL,
	)

	kubectl := &Kubectl{
		options: KubectlOptions{
			serverURL:                client.URL,
			certificateAuthorityPath: "../data/proxy/tls.crt",
		},
	}

	return &User{
		User:    *user,
		Kubectl: kubectl,
		client:  client,
	}, nil
}

func (u *User) Close() {
	u.client.Close()
}
