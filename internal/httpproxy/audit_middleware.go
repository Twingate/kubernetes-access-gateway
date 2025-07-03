// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0
//

package httpproxy

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	errFailedToHijack = errors.New("failed to hijack")
)

type responseWriter struct {
	http.ResponseWriter
	headerWritten bool
	statusCode    int
	headers       http.Header
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.headerWritten = true
	rw.statusCode = code
	rw.headers = rw.Header().Clone()
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(p []byte) (int, error) {
	if !rw.headerWritten {
		// Mirror ResponseWriter.Write behavior by setting 200 status code
		// if no header has been written yet.
		rw.WriteHeader(http.StatusOK)
	}

	return rw.ResponseWriter.Write(p)
}

func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := rw.ResponseWriter.(http.Hijacker); ok {
		conn, brw, err := hijacker.Hijack()
		if err == nil {
			// If the connection is hijacked, the caller will write the response headers and body.
			// We assume it would happen successfully and set the status code to 101.
			rw.headerWritten = true
			rw.statusCode = http.StatusSwitchingProtocols
			rw.headers = rw.Header().Clone()
		}

		return conn, brw, err
	}

	return nil, nil, errFailedToHijack
}

// Compile-time checks that responseWriter implements http.Flusher and http.Hijacker.
var _ http.Flusher = &responseWriter{}  // Support HTTP streaming
var _ http.Hijacker = &responseWriter{} // Support WebSocket streaming

type handlerWithAuditLogger func(w http.ResponseWriter, r *http.Request, conn *ProxyConn, auditLogger *zap.Logger)

type config struct {
	next handlerWithAuditLogger
	//nolint:godox
	// TODO: we should always pass in a logger here instead of falling back to the global logger.
	// For now, if nil, a default logger will be used.
	logger *zap.Logger
}

func auditMiddleware(config config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := config.logger
		if logger == nil {
			logger = zap.L().Named("audit")
		}

		auditLogger := logger.With(
			zap.String("request_id", uuid.New().String()),
			zap.Time("requested_at", time.Now()),
			zap.String("method", r.Method),
			zap.String("url", r.URL.String()),
			zap.String("remote_addr", r.RemoteAddr),
		)
		conn, ok := r.Context().Value(ConnContextKey).(*ProxyConn)

		if !ok {
			auditLogger.Error("Failed to retrieve proxy connection from context")
			http.Error(w, "Internal server error", http.StatusInternalServerError)

			return
		}

		auditLogger = auditLogger.With(
			zap.Object("user", conn.claims.User),
			zap.String("conn_id", conn.id),
		)

		rw := &responseWriter{ResponseWriter: w}

		defer func() {
			// Check if there was a panic. `http.ErrAbortHandler` is considered
			// okay e.g. client closes connection during HTTP streaming.
			if recovered := recover(); recovered != nil && recovered != http.ErrAbortHandler { //nolint:err113,errorlint
				auditLogger.Error("API request failed",
					zap.Any("request", map[string]any{
						"headers": r.Header,
					}),
					zap.Any("response", map[string]any{
						"status_code": rw.statusCode,
						"headers":     rw.headers,
					}),
					zap.Any("panic", recovered),
				)

				// Re-panic to let others handle it
				panic(recovered)
			}

			auditLogger.Info("API request completed",
				zap.Any("request", map[string]any{
					"headers": r.Header,
				}),
				zap.Any("response", map[string]any{
					"status_code": rw.statusCode,
					"headers":     rw.headers,
				}),
			)
		}()

		config.next(rw, r, conn, auditLogger)
	})
}
