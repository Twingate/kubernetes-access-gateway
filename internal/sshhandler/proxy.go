// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"k8sgateway/internal/connect"
)

// Factory for creating SSH Client and Server Connections (downstream and upstream).
type sshConnFactory interface {
	NewServerConn(c net.Conn, config *ssh.ServerConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error)
	NewClientConn(c net.Conn, addr string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error)
}

// NetDialer creates network connections.
type netDialerFactory interface {
	DialTimeout(network, address string, timeout time.Duration) (net.Conn, error)
}

// DefaultSSHConnFactory implements SSHConnFactory using the standard ssh package.
type defaultSSHConnFactory struct{}

//revive:disable-next-line:function-result-limit
//nolint:ireturn
func (f *defaultSSHConnFactory) NewServerConn(c net.Conn, config *ssh.ServerConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	return ssh.NewServerConn(c, config)
}

//revive:disable-next-line:function-result-limit
//nolint:ireturn
func (f *defaultSSHConnFactory) NewClientConn(c net.Conn, addr string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	return ssh.NewClientConn(c, addr, config)
}

// DefaultNetDialer implements NetDialer using the standard net package.
type defaultNetDialer struct{}

func (d *defaultNetDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}

// ConnPairFactory creates an SSH connection pair (downstream and upstream).
type connPairFactory interface {
	NewConnPair(logger *zap.Logger, downstreamConn ssh.Conn, upstreamConn ssh.Conn, downstreamChannels <-chan ssh.NewChannel) ConnPair
}

// DefaultConnPairFactory implements SSHConnPairFactory using SSHConnPair.
type defaultConnPairFactory struct{}

//nolint:ireturn
func (f *defaultConnPairFactory) NewConnPair(logger *zap.Logger, downstreamConn ssh.Conn, upstreamConn ssh.Conn, downstreamChannels <-chan ssh.NewChannel) ConnPair {
	return NewSSHConnPair(logger, downstreamConn, upstreamConn, downstreamChannels)
}

var (
	errUnknownUpstream = errors.New("unknown upstream")
	errShuttingDown    = errors.New("shutting down")
)

// Timeout for connecting to the upstream SSH server.
const upstreamConnTimeout = 10 * time.Second

type ProxyService interface {
	Start()
	Serve(conn connect.Conn) error
	Shutdown()
}

type SSHProxy struct {
	mu sync.Mutex

	// Map of all active SSH connections
	connsMap map[ConnPair]struct{}

	// Wait group for active SSH connections
	wg sync.WaitGroup

	// Configuration for the proxy
	config           Config
	downstreamConfig *ssh.ServerConfig

	// Whether the proxy is shutting down
	shuttingDown bool

	// Dependencies for creating connections (injectable for testing)
	sshConnFactory  sshConnFactory
	netDialer       netDialerFactory
	connPairFactory connPairFactory
}

func NewProxy(config Config) *SSHProxy {
	return &SSHProxy{
		wg:              sync.WaitGroup{},
		mu:              sync.Mutex{},
		connsMap:        map[ConnPair]struct{}{},
		config:          config,
		shuttingDown:    false,
		sshConnFactory:  &defaultSSHConnFactory{},
		netDialer:       &defaultNetDialer{},
		connPairFactory: &defaultConnPairFactory{},
	}
}

func (p *SSHProxy) Start(ctx context.Context) error {
	downstreamConfig, err := p.config.GetDownstreamConfig(ctx)
	if err != nil {
		return err
	}

	p.downstreamConfig = downstreamConfig

	// Start handling incoming SSH connections
	for {
		// Block until a connection is accepted
		conn, err := p.config.ProtocolListener.Accept()
		if err != nil {
			p.config.logger.Error("Failed to accept incoming connection", zap.Error(err))

			break
		}

		// No longer serving
		if conn == nil {
			break
		}

		// Serve SSH connection in a separate goroutine
		go func() {
			err := p.Serve(ctx, conn.(connect.Conn))
			if err != nil {
				p.config.logger.Error("Failed to serve SSH connection", zap.Error(err))
			}
		}()
	}

	return nil
}

func (p *SSHProxy) Serve(ctx context.Context, conn connect.Conn) error {
	p.mu.Lock()

	if p.shuttingDown {
		p.mu.Unlock()
		// reject the connection and return error
		err := conn.Close()
		if err != nil {
			p.config.logger.Error("Failed to close connection", zap.Error(err))
		}

		return errShuttingDown
	}

	p.mu.Unlock()

	return p.serveConn(ctx, conn)
}

func (p *SSHProxy) Shutdown() {
	// Try to close all the connections to cleanup
	p.mu.Lock()

	p.shuttingDown = true
	for conn := range p.connsMap {
		conn.close()
	}

	p.mu.Unlock()

	// Wait for all the goroutines handling the SSH connections to finish
	p.wg.Wait()
}

func (p *SSHProxy) serveConn(ctx context.Context, conn connect.Conn) error {
	p.mu.Lock()

	if p.shuttingDown {
		p.mu.Unlock()
		// reject the connection and return error
		_ = conn.Close()

		return errShuttingDown
	}

	p.mu.Unlock()

	// Setup logger for this connection
	logger := p.config.logger.Named("audit").With(
		zap.Object("user", conn.GATClaims().User),
		zap.String("conn_id", conn.GetID()),
	)

	upstream, exists := p.config.upstreamsByAddress[conn.GetAddress()]
	if !exists {
		logger.Error("Unknown SSH upstream", zap.String("address", conn.GetAddress()))

		_ = conn.Close()

		return fmt.Errorf("%w: %s", errUnknownUpstream, conn.GetAddress())
	}

	// Give the proxyconn.ProxyConn TCP connection to the SSH server to start the SSH handshake
	downstreamSSHConn, downstreamSSHChannelsChan, downstreamSSHRequestsChan, err := p.sshConnFactory.NewServerConn(conn, p.downstreamConfig)
	if err != nil {
		logger.Error("Handshake failed", zap.Error(err))

		_ = conn.Close()

		return err
	}

	logger = logger.With(
		zap.Any("session", map[string]any{
			"id":             hex.EncodeToString(downstreamSSHConn.SessionID()),
			"client_version": string(downstreamSSHConn.ClientVersion()),
		}),
	)

	// Reject all global requests from downstream
	// This disallows `forwarded-tcpip` type of requests
	go ssh.DiscardRequests(downstreamSSHRequestsChan)

	upstreamConfig, err := p.config.GetUpstreamConfig(ctx, upstream)
	if err != nil {
		return err
	}

	// Start connection to upstream SSH server
	upstreamConn, err := p.netDialer.DialTimeout("tcp", upstream.address, upstreamConnTimeout)
	if err != nil {
		logger.Error("Failed to connect to upstream SSH server", zap.Error(err))

		_ = downstreamSSHConn.Close()

		return err
	}

	// Open the SSH connection to the upstream server
	upstreamSSHConn, upstreamSSHChannelsChan, upstreamSSHRequestsChan, err := p.sshConnFactory.NewClientConn(upstreamConn, upstream.address, upstreamConfig)
	if err != nil {
		logger.Error("Failed to connect to upstream SSH server", zap.Error(err))

		_ = downstreamSSHConn.Close()
		_ = upstreamConn.Close()

		return err
	}

	// Reject all channel open requests from upstream
	// This disallows `forwarded-tcpip`, `x11`, and agent forwarding type of requests
	go func() {
		for newChannel := range upstreamSSHChannelsChan {
			err := newChannel.Reject(ssh.Prohibited, "prohibited")
			if err != nil {
				logger.Error("Failed to reject upstream channel", zap.Error(err))
			}
		}
	}()

	// Reject all global requests from upstream
	// This disallows `forwarded-tcpip` and `x11` type of requests
	go ssh.DiscardRequests(upstreamSSHRequestsChan)

	// Create the SSH connection pair using the factory
	sshConnPair := p.connPairFactory.NewConnPair(logger, downstreamSSHConn, upstreamSSHConn, downstreamSSHChannelsChan)

	// Serve the SSH connection pair
	p.wg.Add(1)

	// Add the open SSH connection pair to the map
	p.mu.Lock()
	p.connsMap[sshConnPair] = struct{}{}
	p.mu.Unlock()

	sshConnPair.serve()

	// Remove the closed SSH connection pair from the map
	p.mu.Lock()
	delete(p.connsMap, sshConnPair)
	p.mu.Unlock()

	p.wg.Done()

	return nil
}
