// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"

	"go.uber.org/zap"
)

type ProtocolListener struct {
	parentListener *Listener
	acceptChan     chan Conn
	closed         chan struct{}
	closeOnce      sync.Once
}

func (s *ProtocolListener) Accept() (net.Conn, error) {
	// Check closed first to ensure that
	// Close() followed by Accept() will return ErrClosed
	select {
	case <-s.closed:
		return nil, net.ErrClosed
	default:
	}

	// If not closed, wait for connection or close signal
	select {
	case conn := <-s.acceptChan:
		return conn, nil
	case <-s.closed:
		return nil, net.ErrClosed
	}
}

func (s *ProtocolListener) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
	})

	return nil
}

func (s *ProtocolListener) Addr() net.Addr {
	return s.parentListener.innerListener.Addr()
}

type ConnFactory func(net.Conn, *tls.Config, Validator, *zap.Logger) Conn

type ListenerService interface {
	Serve() error
	GetHTTPListener() *ProtocolListener
	GetSSHListener() *ProtocolListener
	Stop() error
}

type Listener struct {
	innerListener net.Listener

	TLSConfig        *tls.Config
	ConnectValidator Validator
	Logger           *zap.Logger

	// Listener for SSH Connections
	SSHListener *ProtocolListener

	// Listener for HTTP Connections
	HTTPListener *ProtocolListener

	// Factory method for creating ProxyConn
	proxyConnFactory ConnFactory

	// Metrics
	metrics *ProxyConnMetrics
}

func NewListener(listener net.Listener, tlsConfig *tls.Config, connectValidator Validator, metrics *ProxyConnMetrics, logger *zap.Logger) *Listener {
	pl := &Listener{
		innerListener:    listener,
		TLSConfig:        tlsConfig,
		ConnectValidator: connectValidator,
		Logger:           logger,
		metrics:          metrics,
		proxyConnFactory: func(conn net.Conn, tlsConfig *tls.Config, connectValidator Validator, logger *zap.Logger) Conn {
			return &ProxyConn{
				Conn:             conn,
				TLSConfig:        tlsConfig,
				ConnectValidator: connectValidator,
				Logger:           logger,
				tracker:          NewProxyConnMetricsTracker(ConnCategoryUnknown, metrics),
			}
		},
	}

	pl.SSHListener = &ProtocolListener{parentListener: pl, acceptChan: make(chan Conn), closed: make(chan struct{}, 1)}
	pl.HTTPListener = &ProtocolListener{parentListener: pl, acceptChan: make(chan Conn), closed: make(chan struct{}, 1)}

	return pl
}

func (l *Listener) GetHTTPListener() *ProtocolListener {
	return l.HTTPListener
}

func (l *Listener) GetSSHListener() *ProtocolListener {
	return l.SSHListener
}

func (l *Listener) Serve() error {
	for {
		conn, err := l.innerListener.Accept()
		if err != nil {
			l.Logger.Error("Failed to accept connection", zap.Error(err))

			return err
		}

		l.Logger.Debug("Accepted connection", zap.String("remote addr", conn.RemoteAddr().String()))

		go func() {
			proxyConn := l.proxyConnFactory(conn, l.TLSConfig, l.ConnectValidator, l.Logger)

			if err := proxyConn.Authenticate(); err != nil {
				if !errors.Is(err, io.EOF) {
					l.Logger.Error("Failed to authenticate connection", zap.Error(err))
				}

				_ = proxyConn.Close()

				return
			}

			if proxyConn.TransportProtocol() == TransportSSH {
				select {
				case l.SSHListener.acceptChan <- proxyConn:
					// Connection accepted
				case <-l.SSHListener.closed:
					// Listener is closed, close the connection
					_ = proxyConn.Close()
				}
			} else {
				if err := proxyConn.UpgradeToTLS(); err != nil {
					_ = proxyConn.Close()

					return
				}

				select {
				case l.HTTPListener.acceptChan <- proxyConn:
					// Connection accepted
				case <-l.HTTPListener.closed:
					// Listener is closed, close the connection
					_ = proxyConn.Close()
				}
			}
		}()
	}
}

func (l *Listener) Stop() error {
	err := l.SSHListener.Close()
	if err != nil {
		l.Logger.Error("Failed to close SSH listener", zap.Error(err))
	}

	err = l.HTTPListener.Close()
	if err != nil {
		l.Logger.Error("Failed to close HTTPS listener", zap.Error(err))
	}

	err = l.innerListener.Close()
	if err != nil {
		l.Logger.Error("Failed to close listener", zap.Error(err))
	}

	return err
}
