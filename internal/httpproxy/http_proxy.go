package httpproxy

import (
	"bufio"
	"bytes"
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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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

const (
	bodyLogMaxSize           = 16 * 1024 // 16KB
	bodyLogTruncationSuffix  = " ... [truncated]"
	bodyLogMaxSizeWithSuffix = bodyLogMaxSize - len(bodyLogTruncationSuffix)
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

// ProxyConn is a custom connection that wraps the underlying TCP net.Conn, handling downstream
// proxy (Twingate Client)'s authentication via the initial CONNECT message. It handles 2 TLS
// upgrades: with downstream proxy and then with downstream client e.g. `kubectl`.
type ProxyConn struct {
	net.Conn
	TLSConfig        *tls.Config
	ConnectValidator connect.Validator
	logger           *zap.Logger

	isAuthenticated bool

	id     string
	claims *token.GATClaims
	timer  *time.Timer
	mu     sync.Mutex
}

func (p *ProxyConn) Read(b []byte) (int, error) {
	if p.isAuthenticated {
		return p.Conn.Read(b)
	}

	if err := p.authenticate(); err != nil {
		return 0, err
	}

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
		tlsConnectConn.Close()

		return err
	}

	// parse HTTP request
	bufReader := bufio.NewReader(tlsConnectConn)

	req, err := http.ReadRequest(bufReader)
	if err != nil {
		p.logger.Error("failed to parse HTTP request", zap.Error(err))

		responseStr := "HTTP/1.1 400 Bad Request\r\n\r\n"

		_, writeErr := tlsConnectConn.Write([]byte(responseStr))
		if writeErr != nil {
			p.logger.Error("failed to write response", zap.Error(writeErr))
			tlsConnectConn.Close()

			return writeErr
		}

		tlsConnectConn.Close()

		return err
	}

	// Health check request
	if req.Method == http.MethodGet && req.URL.Path == healthCheckPath {
		responseStr := "HTTP/1.1 200 OK\r\n\r\n"

		_, writeErr := tlsConnectConn.Write([]byte(responseStr))
		if writeErr != nil {
			p.logger.Error("failed to write response", zap.Error(writeErr))
			tlsConnectConn.Close()

			return writeErr
		}

		tlsConnectConn.Close()

		return nil
	}

	// get the keying material for the TLS session
	ekm, err := ExportKeyingMaterial(tlsConnectConn)
	if err != nil {
		p.logger.Error("failed to get keying material", zap.Error(err))
		tlsConnectConn.Close()

		return err
	}

	// Parse and validate HTTP request, expecting CONNECT with
	// valid token and signature
	response := httpResponseString(http.StatusOK)

	connectInfo, err := p.ConnectValidator.ParseConnect(req, ekm)
	if err != nil {
		var httpErr *connect.HTTPError
		if errors.As(err, &httpErr) {
			response = httpResponseString(httpErr.Code)
		} else {
			p.logger.Error("failed to parse CONNECT:", zap.Error(err))

			response = httpResponseString(http.StatusBadRequest)
		}
	}

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
		tlsConnectConn.Close()

		return writeErr
	}

	if err != nil {
		p.logger.Error("failed to serve request", zap.Error(err))
		tlsConnectConn.Close()

		return err
	}

	// CONNECT from downstream proxy is finished, now perform handshake with the downstream client
	tlsConn := tls.Server(tlsConnectConn, p.TLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()

		return err
	}

	// Replace the underlying connection with the downstream client TLS connection
	p.Conn = tlsConn
	p.setConnectInfo(connectInfo)
	p.isAuthenticated = true

	return nil
}

func (p *ProxyConn) setConnectInfo(connectInfo connect.Info) {
	p.mu.Lock()
	defer p.mu.Unlock()

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

	return &ProxyConn{
		Conn:             conn,
		TLSConfig:        l.TLSConfig,
		ConnectValidator: l.ConnectValidator,
		logger:           l.logger,
	}, nil
}

type responseLogger struct {
	http.ResponseWriter
	statusCode int
	headers    http.Header
	body       *bytes.Buffer
}

func (rl *responseLogger) WriteHeader(code int) {
	rl.statusCode = code
	rl.headers = rl.Header().Clone()
	rl.ResponseWriter.WriteHeader(code)
}

func (rl *responseLogger) Write(p []byte) (int, error) {
	rl.body.Write(p)

	return rl.ResponseWriter.Write(p)
}

func (rl *responseLogger) Flush() {
	if flusher, ok := rl.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func truncateBody(body []byte) string {
	if len(body) > bodyLogMaxSize {
		return string(body[:bodyLogMaxSizeWithSuffix]) + bodyLogTruncationSuffix
	}

	return string(body)
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
	mux.HandleFunc("/", p.serveHTTP)
	mux.HandleFunc("GET /api/v1/namespaces/{namespace}/pods/{pod}/exec", p.serveHTTP)

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

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	auditLogger := zap.L().Named("audit").With(
		zap.String("request_id", uuid.New().String()),
		zap.String("method", r.Method),
		zap.String("url", r.URL.String()),
		zap.String("remote_addr", r.RemoteAddr),
	)
	conn, ok := r.Context().Value(ConnContextKey).(*ProxyConn)

	if !ok {
		auditLogger.Error("Failed to retrieve net.Conn from context")
		http.Error(w, "Internal server error", http.StatusInternalServerError)

		return
	}

	auditLogger = auditLogger.With(
		zap.Object("user", conn.claims.User),
		zap.String("conn_id", conn.id),
	)

	// read the body, consuming the data
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		auditLogger.Error("failed to read request body", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)

		return
	}

	// close and recreate the body reader
	if err := r.Body.Close(); err != nil {
		auditLogger.Error("failed to process request body", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)

		return
	}

	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// truncate the body log if it's too large
	logReqBody := truncateBody(bodyBytes)

	auditLogger.Info("API request",
		zap.Namespace("request"),
		zap.Any("header", r.Header),
		zap.String("body", logReqBody),
	)

	isWebSocketRequest := wsstream.IsWebSocketRequest(r)

	switch {
	case isWebSocketRequest && !shouldSkipWebSocketRequest(r):
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
	case !isWebSocketRequest && !shouldSkipRESTRequest(r):
		// Audit REST API response
		responseLogger := &responseLogger{ResponseWriter: w, statusCode: http.StatusOK, body: &bytes.Buffer{}}
		defer func() {
			// truncate the body log if it's too large
			logResBody := truncateBody(responseLogger.body.Bytes())

			auditLogger.Info("API response",
				zap.Namespace("response"),
				zap.Int("status_code", responseLogger.statusCode),
				zap.Any("header", responseLogger.headers),
				zap.String("body", logResBody),
			)
		}()
		p.proxy.ServeHTTP(responseLogger, r)
	default:
		// No audit
		p.proxy.ServeHTTP(w, r)
	}
}

var podLogPattern = regexp.MustCompile(`^/api/v1/namespaces/[^/]+/pods/[^/]+/log$`)

func shouldSkipWebSocketRequest(r *http.Request) bool {
	// Skip tunneling requests (e.g. `kubectl proxy`)
	return wsstream.IsWebSocketRequestWithTunnelingProtocol(r) ||
		// Skip file transferring from `kubectl cp`
		r.Header.Get("Kubectl-Command") == "kubectl cp" ||
		// Skip executing `tar` command
		r.URL.Query().Get("command") == "tar"
}

func shouldSkipRESTRequest(r *http.Request) bool {
	// Skip requests for pod logs
	return podLogPattern.MatchString(r.URL.Path)
}
