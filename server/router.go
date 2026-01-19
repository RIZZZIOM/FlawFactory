package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/RIZZZIOM/FlawFactory/logger"
)

// Router handles HTTP routing
type Router struct {
	mux    *http.ServeMux
	logger *logger.Logger
}

// NewRouter creates a new router with optional JSON logging
func NewRouter(jsonLogger *logger.Logger) *Router {
	return &Router{
		mux:    http.NewServeMux(),
		logger: jsonLogger,
	}
}

// ServeHTTP implements http.Handler interface
// This allows Router to be used as an HTTP handler
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Log the request
	start := time.Now()

	// Capture request body for logging (if applicable)
	var bodyBytes []byte
	if req.Body != nil && (req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch) {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body.Close()
		// Restore the body so handlers can still read it
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Store body in context for the logger
	ctx := context.WithValue(req.Context(), logger.RequestBodyKey, bodyBytes)
	req = req.WithContext(ctx)

	// Create a response writer that captures the status code and content length
	wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

	// Serve the request
	r.mux.ServeHTTP(wrapped, req)

	// Log after request is handled
	duration := time.Since(start)

	// Console log (existing behavior)
	log.Printf("[%s] %s %s - %d - %v",
		time.Now().Format("2006-01-02 15:04:05"),
		req.Method,
		req.URL.Path,
		wrapped.statusCode,
		duration,
	)

	// JSON file log (if logger is configured)
	if r.logger != nil {
		if err := r.logger.LogRequest(req, wrapped.statusCode, duration, wrapped.contentLength); err != nil {
			log.Printf("Warning: failed to log request to JSON file: %v", err)
		}
	}
}

// HandleFunc registers a handler function for a path and method
func (r *Router) HandleFunc(method, path string, handler http.HandlerFunc) {
	pattern := fmt.Sprintf("%s %s", method, path)
	r.mux.HandleFunc(pattern, handler)
	log.Printf("Registered route: %s %s", method, path)
}

// responseWriter wraps http.ResponseWriter to capture status code and content length
type responseWriter struct {
	http.ResponseWriter
	statusCode    int
	contentLength int64
}

// WriteHeader captures the status code
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write captures the content length
func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.contentLength += int64(n)
	return n, err
}
