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

	"k8sgateway/internal/connect"
	"k8sgateway/internal/token"
	"k8sgateway/internal/wsproxy"
)

type connContextKey string

const healthCheckPath = "/healthz"
const ConnContextKey connContextKey = "CONN_CONTEXT"

const secretLen = 32

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
	K8sAPIServerCA    string
	ConnectValidator  connect.Validator
	Port              int
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
	cs := tlsConnectConn.ConnectionState()

	ekm, err := cs.ExportKeyingMaterial("EXPERIMENTAL_twingate_gat", nil, secretLen)
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
	httpServer          *http.Server
	proxy               *httputil.ReverseProxy
	downstreamTLSConfig *tls.Config
	port                int
	connectValidator    connect.Validator
	k8sAPIServerToken   string
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
		logger.Fatalf("failed to read K8sAPIServerCA cert: %v", err)
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
	transport := &http.Transport{
		TLSClientConfig: upstreamTLSConfig,
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			conn, ok := r.In.Context().Value(ConnContextKey).(*ProxyConn)
			if !ok {
				logger.Errorf("Failed to retrieve net.Conn from context")

				return
			}

			targetURL := &url.URL{
				Scheme: "https",
				Host:   conn.claims.Resource.Address,
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

			// Set authorization and impersonation header to impersonate the user
			// identified from downstream.
			r.Out.Header.Set("Authorization", "Bearer "+cfg.K8sAPIServerToken)
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
		port:                cfg.Port,
		connectValidator:    cfg.ConnectValidator,
		k8sAPIServerToken:   cfg.K8sAPIServerToken,
	}
	mux.HandleFunc("/", p.serveHTTP)
	mux.HandleFunc("GET /api/v1/namespaces/{namespace}/pods/{pod}/exec", p.serveHTTP)

	return p, nil
}

func (p *Proxy) Start(ready chan struct{}) {
	logger := zap.S()

	// create the TCP listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.port))
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
		ConnectValidator: p.connectValidator,
	}

	// start serving HTTP
	err = p.httpServer.Serve(customListener)
	if err != nil {
		logger.Fatal(err)
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
			return wsproxy.NewRecorder(auditLogger)
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
