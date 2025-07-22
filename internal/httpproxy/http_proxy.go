// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/httpstream/wsstream"

	k8stransport "k8s.io/client-go/transport"

	"k8sgateway/internal/connect"
	"k8sgateway/internal/metrics"
	"k8sgateway/internal/token"
	"k8sgateway/internal/wsproxy"
)

type connContextKey string

const healthCheckPath = "/healthz"
const ConnContextKey connContextKey = "CONN_CONTEXT"

const (
	keyingMaterialLabel  = "EXPERIMENTAL_twingate_gat"
	keyingMaterialLength = 32
)

func httpResponseString(httpCode int) string {
	return fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", httpCode, http.StatusText(httpCode))
}

type Config struct {
	TLSCert           string
	TLSKey            string
	K8sAPIServerToken string
	// Path to a file containing a BearerToken.
	// If set, the contents are periodically read.
	// The last successfully read value takes precedence over BearerToken.
	K8sAPIServerTokenFile string
	K8sAPIServerCA        string
	K8sAPIServerPort      int

	ConnectValidator connect.Validator
	Port             int

	LogFlushSizeThreshold int
	LogFlushInterval      time.Duration

	Registry *prometheus.Registry
}

// ProxyConn is a custom connection that wraps the underlying TCP net.Conn, handling downstream
// proxy (Twingate Client)'s authentication via the initial CONNECT message. It handles 2 TLS
// upgrades: with downstream proxy and then with downstream client e.g. `kubectl`.
type ProxyConn struct {
	net.Conn

	tcpConn *connWithMetrics

	TLSConfig        *tls.Config
	ConnectValidator connect.Validator
	logger           *zap.Logger

	isAuthenticated bool

	id     string
	claims *token.GATClaims
	timer  *time.Timer
	mu     sync.Mutex
	start  time.Time
}

func (p *ProxyConn) Read(b []byte) (int, error) {
	p.mu.Lock()

	if p.isAuthenticated {
		p.mu.Unlock()

		return p.Conn.Read(b)
	}

	if err := p.authenticate(); err != nil {
		p.mu.Unlock()

		return 0, err
	}

	p.mu.Unlock()

	return p.Conn.Read(b)
}

func (p *ProxyConn) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.timer != nil {
		p.timer.Stop()
	}

	return p.Conn.Close()
}

// authenticate sets up TLS and processes the CONNECT message for authentication.
func (p *ProxyConn) authenticate() error {
	// Establish TLS connection with the downstream proxy
	tlsConnectConn := tls.Server(p.Conn, p.TLSConfig)

	if err := tlsConnectConn.Handshake(); err != nil {
		return err
	}

	// Replace the underlying connection with the downstream proxy TLS connection
	p.Conn = tlsConnectConn

	// parse HTTP request
	bufReader := bufio.NewReader(tlsConnectConn)

	req, err := http.ReadRequest(bufReader)
	if err != nil {
		p.logger.Error("failed to parse HTTP request", zap.Error(err))

		responseStr := "HTTP/1.1 400 Bad Request\r\n\r\n"

		_, writeErr := tlsConnectConn.Write([]byte(responseStr))
		if writeErr != nil {
			p.logger.Error("failed to write response", zap.Error(writeErr))

			return writeErr
		}

		return err
	}

	// Health check request
	if isHealthCheckRequest(req) {
		p.tcpConn.connCategory = connCategoryHealth

		responseStr := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

		_, writeErr := tlsConnectConn.Write([]byte(responseStr))
		if writeErr != nil {
			p.logger.Error("failed to write response", zap.Error(writeErr))

			return writeErr
		}

		return io.EOF
	}

	p.tcpConn.connCategory = connCategoryProxy

	// get the keying material for the TLS session
	ekm, err := ExportKeyingMaterial(tlsConnectConn)
	if err != nil {
		p.logger.Error("failed to get keying material", zap.Error(err))

		return err
	}

	// Parse and validate HTTP request, expecting CONNECT with
	// valid token and signature
	httpCode := http.StatusOK

	connectInfo, err := p.ConnectValidator.ParseConnect(req, ekm)
	if err != nil {
		var httpErr *connect.HTTPError
		if errors.As(err, &httpErr) {
			httpCode = httpErr.Code
		} else {
			p.logger.Error("failed to parse CONNECT:", zap.Error(err))

			httpCode = http.StatusBadRequest
		}
	}

	response := httpResponseString(httpCode)

	if connectInfo.Claims != nil {
		p.logger = p.logger.With(
			zap.Object("user", connectInfo.Claims.User),
		)
	}

	p.logger = p.logger.With(
		zap.String("conn_id", connectInfo.ConnID),
	)

	_, writeErr := tlsConnectConn.Write([]byte(response))
	if writeErr != nil {
		p.logger.Error("failed to write response", zap.Error(writeErr))

		return writeErr
	}

	if err != nil {
		p.logger.Error("failed to serve request", zap.Error(err))

		return err
	}

	codeStr := strconv.Itoa(httpCode)
	connect.RecordConnectDuration(p.start, codeStr)
	connect.RecordConnectTotal(codeStr)

	// CONNECT from downstream proxy is finished, now perform handshake with the downstream client
	tlsConn := tls.Server(tlsConnectConn, p.TLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	// Replace the underlying connection with the downstream client TLS connection
	p.Conn = tlsConn
	p.setConnectInfo(connectInfo)
	p.isAuthenticated = true

	return nil
}

func (p *ProxyConn) setConnectInfo(connectInfo connect.Info) {
	p.id = connectInfo.ConnID
	p.claims = connectInfo.Claims
	p.timer = time.AfterFunc(time.Until(connectInfo.Claims.ExpiresAt.Time), func() {
		_ = p.Close()
	})
}

func ExportKeyingMaterial(conn *tls.Conn) ([]byte, error) {
	cs := conn.ConnectionState()

	return cs.ExportKeyingMaterial(keyingMaterialLabel, nil, keyingMaterialLength)
}

type proxyListener struct {
	net.Listener

	TLSConfig        *tls.Config
	ConnectValidator connect.Validator
	logger           *zap.Logger
}

func (l *proxyListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	tcpConn := newConnWithMetrics(conn)

	return &ProxyConn{
		Conn:             tcpConn,
		tcpConn:          tcpConn, // Keep the underlying TCP conn reference
		TLSConfig:        l.TLSConfig,
		ConnectValidator: l.ConnectValidator,
		logger:           l.logger,
		start:            time.Now(),
	}, nil
}

type ProxyService interface {
	Start(ready chan struct{})
}

type Proxy struct {
	config              Config
	httpServer          *http.Server
	proxy               *httputil.ReverseProxy
	downstreamTLSConfig *tls.Config
}

func NewProxy(cfg Config) (*Proxy, error) {
	logger := zap.S()

	if cfg.ConnectValidator == nil {
		logger.Fatal("connect validator is nil")
	}

	// create TLS configuration for downstream
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		logger.Fatalf("failed to load TLS certificate: %v", err)
	}

	logger.Infof("loaded downstream TLS certs")

	downstreamTLSConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}

	// create TLS configuration for upstream
	caCert, err := os.ReadFile(cfg.K8sAPIServerCA)
	if err != nil {
		logger.Fatalf("failed to read CA cert: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		logger.Fatal("failed to append K8sAPIServerCA cert to pool")
	}

	logger.Infof("loaded upstream K8sAPIServerCA cert")

	upstreamTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    caCertPool,
	}

	transport, err := k8stransport.NewBearerAuthWithRefreshRoundTripper(
		cfg.K8sAPIServerToken,
		cfg.K8sAPIServerTokenFile,
		&http.Transport{
			TLSClientConfig: upstreamTLSConfig,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create bearer auth round tripper: %w", err)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			conn, ok := r.In.Context().Value(ConnContextKey).(*ProxyConn)
			if !ok {
				logger.Errorf("Failed to retrieve net.Conn from context")

				return
			}

			apiServerAddress := conn.claims.Resource.Address
			if cfg.K8sAPIServerPort != 0 {
				apiServerAddress = fmt.Sprintf("%s:%d", conn.claims.Resource.Address, cfg.K8sAPIServerPort)
			}
			targetURL := &url.URL{
				Scheme: "https",
				Host:   apiServerAddress,
			}
			r.SetURL(targetURL)

			// As a precaution, remove existing k8s related headers from downstream.
			r.Out.Header.Del("Authorization")
			r.Out.Header.Del("Impersonate-User")
			r.Out.Header.Del("Impersonate-Group")
			r.Out.Header.Del("Impersonate-Uid")
			for k := range r.Out.Header {
				if strings.HasPrefix(k, "Impersonate-Extra-") {
					r.Out.Header.Del(k)
				}
			}

			// Set impersonation header to impersonate the user
			// identified from downstream.
			r.Out.Header.Set("Impersonate-User", conn.claims.User.Username)
			for _, group := range conn.claims.User.Groups {
				r.Out.Header.Add("Impersonate-Group", group)
			}
		},
		Transport: metrics.RoundTripper(metrics.RoundTripperConfig{
			Registry: cfg.Registry,
			Next:     transport,
		}),
	}

	mux := http.NewServeMux()
	httpServer := &http.Server{
		// G112 - Protect against Slowloris attack
		ReadHeaderTimeout: 5 * time.Second,

		Handler: mux,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// add the net.Conn to the context so we can track this connection, this context
			// will be merged with and retrievable in the http.Request that is passed in to the Handler func and
			// since our custom listener provided a wrapped net.Conn (ProxyConn), its fields will be
			// available, specifically the identity information parsed from CONNECT
			return context.WithValue(ctx, ConnContextKey, c)
		},
	}

	p := &Proxy{
		httpServer:          httpServer,
		proxy:               proxy,
		downstreamTLSConfig: downstreamTLSConfig,
		config:              cfg,
	}
	registerConnMetrics(cfg.Registry)
	connect.RegisterConnectMetrics(cfg.Registry)
	handler := metrics.HTTPMiddleware(metrics.HTTPMiddlewareConfig{
		Registry: cfg.Registry,
		Next: auditMiddleware(config{
			next: p.serveHTTP,
		}),
	})
	mux.Handle("/", handler)
	mux.Handle("GET /api/v1/namespaces/{namespace}/pods/{pod}/exec", handler)

	return p, nil
}

func (p *Proxy) Start(ready chan struct{}) {
	logger := zap.L()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.config.Port))
	if err != nil {
		logger.Fatal("failed to create listener", zap.Error(err))
	}

	if ready != nil {
		close(ready)
	}

	listener = &proxyListener{
		Listener:         listener,
		TLSConfig:        p.downstreamTLSConfig,
		ConnectValidator: p.config.ConnectValidator,
		logger:           logger,
	}

	err = p.httpServer.Serve(listener)
	if err != nil {
		logger.Fatal("failed to start HTTP server", zap.Error(err))
	}
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request, conn *ProxyConn, auditLogger *zap.Logger) {
	switch {
	case wsstream.IsWebSocketRequest(r) && !shouldSkipWebSocketRequest(r):
		// Audit Websocket streaming session
		recorderFactory := func() wsproxy.Recorder {
			return wsproxy.NewRecorder(
				auditLogger,
				wsproxy.WithFlushSizeThreshold(p.config.LogFlushSizeThreshold),
				wsproxy.WithFlushInterval(p.config.LogFlushInterval),
			)
		}
		wsHijacker := wsproxy.NewHijacker(r, w, conn.claims.User.Username, recorderFactory, wsproxy.NewConn)
		p.proxy.ServeHTTP(wsHijacker, r)
	default:
		p.proxy.ServeHTTP(w, r)
	}
}

func shouldSkipWebSocketRequest(r *http.Request) bool {
	// Skip tunneling requests (e.g. `kubectl proxy`)
	return wsstream.IsWebSocketRequestWithTunnelingProtocol(r) ||
		// Skip file transferring from `kubectl cp`
		r.Header.Get("Kubectl-Command") == "kubectl cp" ||
		// Skip executing `tar` command
		r.URL.Query().Get("command") == "tar"
}

func isHealthCheckRequest(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.Path == healthCheckPath
}
