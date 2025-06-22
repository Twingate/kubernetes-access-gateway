package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/httpstream/wsstream"

	k8stransport "k8s.io/client-go/transport"

	"k8sgateway/internal/connect"
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
}

// custom Conn that wraps a net.Conn, adding the user identity field.
type ProxyConn struct {
	net.Conn
	id     string
	claims *token.GATClaims
	timer  *time.Timer
	mu     sync.Mutex
}

func NewProxyConn(conn net.Conn, connID string, claims *token.GATClaims) *ProxyConn {
	p := &ProxyConn{
		Conn:   conn,
		id:     connID,
		claims: claims,
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.timer = time.AfterFunc(time.Until(claims.ExpiresAt.Time), func() {
		_ = p.Close()
	})

	return p
}

func (p *ProxyConn) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.timer != nil {
		p.timer.Stop()
	}

	return p.Conn.Close()
}

func ExportKeyingMaterial(conn *tls.Conn) ([]byte, error) {
	cs := conn.ConnectionState()

	return cs.ExportKeyingMaterial(keyingMaterialLabel, nil, keyingMaterialLength)
}

// custom listener to handle HTTP CONNECT and then upgrade to HTTPS.
type tcpListener struct {
	Listener         net.Listener
	TLSConfig        *tls.Config
	ConnectValidator connect.Validator
}

func (l *tcpListener) Accept() (net.Conn, error) {
	logger := zap.S()

	// start accepting connections
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// now upgrade the net.Conn to a TLS connection
	tlsConnectConn := tls.Server(conn, l.TLSConfig)

	// start TLS handshake with the downstream proxy
	if err := tlsConnectConn.Handshake(); err != nil {
		tlsConnectConn.Close()

		return tlsConnectConn, nil //nolint:nilerr
	}

	// parse HTTP request
	bufReader := bufio.NewReader(tlsConnectConn)

	req, err := http.ReadRequest(bufReader)
	if err != nil {
		logger.Errorf("failed to parse HTTP request: %v", err)

		responseStr := "HTTP/1.1 400 Bad Request\r\n\r\n"

		_, writeErr := tlsConnectConn.Write([]byte(responseStr))
		if writeErr != nil {
			logger.Errorf("failed to write response: %v", writeErr)
			tlsConnectConn.Close()

			return tlsConnectConn, nil
		}

		tlsConnectConn.Close()

		return tlsConnectConn, nil
	}

	if req.Method == http.MethodGet && req.URL.Path == healthCheckPath {
		responseStr := "HTTP/1.1 200 OK\r\n\r\n"

		_, writeErr := tlsConnectConn.Write([]byte(responseStr))
		if writeErr != nil {
			logger.Errorf("failed to write response: %v", writeErr)
			tlsConnectConn.Close()

			return tlsConnectConn, nil
		}

		tlsConnectConn.Close()

		return tlsConnectConn, nil
	}

	// get the keying material for the TLS session
	ekm, err := ExportKeyingMaterial(tlsConnectConn)
	if err != nil {
		logger.Errorf("failed to get keying material: %v", err)
		tlsConnectConn.Close()

		return tlsConnectConn, nil
	}

	// Parse and validate HTTP request, expecting CONNECT with
	// valid token and signature
	response := httpResponseString(http.StatusOK)

	connectInfo, err := l.ConnectValidator.ParseConnect(req, ekm)
	if err != nil {
		var httpErr *connect.HTTPError
		if errors.As(err, &httpErr) {
			response = httpResponseString(httpErr.Code)
		} else {
			logger.Error("failed to parse CONNECT:", zap.Error(err))

			response = httpResponseString(http.StatusBadRequest)
		}
	}

	if connectInfo.Claims != nil {
		logger = logger.With(
			zap.Object("user", connectInfo.Claims.User),
		)
	}

	logger = logger.With(
		zap.String("conn_id", connectInfo.ConnID),
	)

	_, writeErr := tlsConnectConn.Write([]byte(response))
	if writeErr != nil {
		logger.Errorf("failed to write response: %v", writeErr)
		tlsConnectConn.Close()

		return tlsConnectConn, nil
	}

	if err != nil {
		logger.Errorf("failed to serve request: %v", err)
		tlsConnectConn.Close()

		return tlsConnectConn, nil
	}

	// CONNECT from downstream proxy is finished, now perform handshake with the downstream client
	tlsConn := tls.Server(tlsConnectConn, l.TLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()

		return tlsConn, nil //nolint:nilerr
	}

	// add auth information to the net.Conn by using ProxyConn which wraps net.Conn with
	// a field for the user identity
	proxyConn := NewProxyConn(tlsConn, connectInfo.ConnID, connectInfo.Claims)

	// return the wrapped and 'upgraded to TLS' net.Conn (ProxyConn) to the caller
	return proxyConn, nil
}

func (l *tcpListener) Close() error {
	return l.Listener.Close()
}

func (l *tcpListener) Addr() net.Addr {
	return l.Listener.Addr()
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
		logger.Fatalf("connect validator is nil")
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
		logger.Fatalf("failed to append K8sAPIServerCA cert to pool")
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
		Transport: transport,
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
	handler := auditMiddleware(config{
		next: p.serveHTTP,
	})
	mux.Handle("/", handler)
	mux.Handle("GET /api/v1/namespaces/{namespace}/pods/{pod}/exec", handler)

	return p, nil
}

func (p *Proxy) Start(ready chan struct{}) {
	logger := zap.S()

	// create the TCP listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.config.Port))
	if err != nil {
		logger.Fatal(err)
	}

	if ready != nil {
		close(ready)
	}

	// use custom listener with TLS config
	customListener := &tcpListener{
		Listener:         listener,
		TLSConfig:        p.downstreamTLSConfig,
		ConnectValidator: p.config.ConnectValidator,
	}

	// start serving HTTP
	err = p.httpServer.Serve(customListener)
	if err != nil {
		logger.Fatal(err)
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
