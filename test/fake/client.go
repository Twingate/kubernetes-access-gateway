// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package fake

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"go.uber.org/zap"

	"k8sgateway/internal/httpproxy"
	"k8sgateway/internal/token"
)

// Client simulates a Twingate Client, authenticating and forwarding kubectl requests to the Gateway.
//
// Client is implemented as a TCP proxy. On receiving a connection, it opens a connection to the
// Gateway, authenticates using a CONNECT request, and then forwards TCP data.
//
// kubectl CLI needs to connect to this Client's listener address.
type Client struct {
	Listener net.Listener
	URL      string

	user          *token.User
	proxyAddress  string
	controllerURL string
	apiServerURL  *url.URL

	cancel context.CancelFunc
	wg     *sync.WaitGroup

	logger *zap.Logger
}

// apiServerURL must include both the protocol and the port.
func NewClient(user *token.User, proxyAddress, controllerURL, apiServerURL string) *Client {
	logger := zap.Must(zap.NewDevelopment()).Named(fmt.Sprintf("client-%s-%s", user.ID, user.Username))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		logger.Fatal("Failed to listen", zap.Error(err))

		return nil
	}

	parsedAPIServerURL, err := url.Parse(apiServerURL)
	if err != nil {
		logger.Fatal("Failed to parse API server URL", zap.Error(err))

		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	c := &Client{
		Listener:      listener,
		URL:           "https://" + listener.Addr().String(),
		proxyAddress:  proxyAddress,
		controllerURL: controllerURL,
		apiServerURL:  parsedAPIServerURL,
		user:          user,
		cancel:        cancel,
		wg:            &sync.WaitGroup{},
		logger:        logger,
	}
	go c.serve(ctx)

	return c
}

// Close gracefully shuts down the client.
//
// It will close the listener and wait for all existing connections to complete. It does not
// terminate existing connections forcibly i.e. it might hang indefinitely if the downstream
// connection is not properly closed.
func (c *Client) Close() {
	c.cancel()

	if err := c.Listener.Close(); err != nil {
		c.logger.Error("Failed to close listener", zap.Error(err))
	}

	c.wg.Wait()
}

func (c *Client) serve(ctx context.Context) {
	for {
		clientConn, err := c.Listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				c.logger.Error("Failed to accept connection", zap.Error(err))
			}

			continue
		}

		gat, err := c.fetchGAT()
		if err != nil {
			c.logger.Error("Failed to fetch GAT", zap.Error(err))

			return
		}

		c.wg.Add(1)

		go c.handleConnection(ctx, clientConn, gat)
	}
}

func (c *Client) handleConnection(ctx context.Context, clientConn net.Conn, gat string) {
	defer clientConn.Close()
	defer c.wg.Done()

	// Proxy certs
	caCert, _ := ReadFileFromProjectDirectory("./test/data/proxy/tls.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: c.apiServerURL.Hostname(),
		RootCAs:    caCertPool,
	}

	// Manually create a TCP connection
	conn, err := net.Dial("tcp", c.proxyAddress)
	if err != nil {
		c.logger.Error("Failed to connect to proxy", zap.Error(err))
	}
	defer conn.Close()

	// Enable outer TLS (between Twingate client and proxy)
	proxyTLSConn := tls.Client(conn, tlsConfig)
	if err := proxyTLSConn.Handshake(); err != nil {
		c.logger.Error("TLS handshake failed(proxy)", zap.Error(err))

		return
	}
	defer proxyTLSConn.Close()

	// Create CONNECT request
	connectReq, err := http.NewRequest(http.MethodConnect, c.apiServerURL.String(), nil)
	if err != nil {
		c.logger.Error("Failed to create request", zap.Error(err))

		return
	}

	connectReq.Header.Set("Proxy-Authorization", "Bearer "+gat)

	clientKey, _ := ReadECKey("./test/data/client/key.pem")
	ekm, _ := httpproxy.ExportKeyingMaterial(proxyTLSConn)
	ekmHash := sha256.Sum256(ekm)
	signature, _ := ecdsa.SignASN1(rand.Reader, clientKey, ekmHash[:])
	b64Signature := base64.StdEncoding.EncodeToString(signature)
	connectReq.Header.Set("X-Token-Signature", b64Signature)

	// Send CONNECT request
	if err := connectReq.Write(proxyTLSConn); err != nil {
		c.logger.Error("Failed to write CONNECT request", zap.Error(err))

		return
	}

	// Read CONNECT response
	connectResp, err := http.ReadResponse(bufio.NewReader(proxyTLSConn), connectReq)
	if err != nil {
		c.logger.Error("Failed to read CONNECT response", zap.Error(err))

		return
	}
	defer connectResp.Body.Close()

	c.logger.Info("Connect response", zap.Int("status code", connectResp.StatusCode))

	// Set up bidirectional copy
	copyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		_, _ = io.Copy(proxyTLSConn, clientConn)

		cancel()
	}()
	go func() {
		_, _ = io.Copy(clientConn, proxyTLSConn)

		cancel()
	}()

	<-copyCtx.Done()
}

func (c *Client) fetchGAT() (string, error) {
	clientPublicKey, _ := ReadECKey("./test/data/client/key.pem")
	requestBody := requestBody{
		ClientPublicKey: &token.PublicKey{
			PublicKey: clientPublicKey.PublicKey,
		},
		User: c.user,
		Device: &token.Device{
			ID: "device-1",
		},
		Resource: &token.Resource{
			ID:      "resource-1",
			Address: c.apiServerURL.Hostname(),
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		c.logger.Error("Failed to marshal request body", zap.Error(err))

		return "", err
	}

	resp, err := http.Post(c.controllerURL+"/api/v1/gat", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		c.logger.Error("Failed to fetch GAT", zap.Error(err))

		return "", err
	}
	defer resp.Body.Close()

	gat, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Error("Failed to read GAT response", zap.Error(err))

		return "", err
	}

	return string(gat), nil
}
