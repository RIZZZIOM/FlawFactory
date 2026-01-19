package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RequestLog represents a single HTTP request log entry
type RequestLog struct {
	Timestamp     string            `json:"timestamp"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	QueryParams   map[string]string `json:"query_params,omitempty"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body,omitempty"`
	RemoteAddr    string            `json:"remote_addr"`
	StatusCode    int               `json:"status_code"`
	ResponseTime  string            `json:"response_time"`
	ContentLength int64             `json:"content_length,omitempty"`
}

// Logger handles JSON logging to a file
type Logger struct {
	file     *os.File
	encoder  *json.Encoder
	mu       sync.Mutex
	filePath string
}

// New creates a new Logger that writes to the specified file
// If the directory doesn't exist, it will be created
func New(logFilePath string) (*Logger, error) {
	// Create the directory if it doesn't exist
	dir := filepath.Dir(logFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open the file for appending (create if doesn't exist)
	file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return &Logger{
		file:     file,
		encoder:  json.NewEncoder(file),
		filePath: logFilePath,
	}, nil
}

// LogRequest logs an HTTP request to the JSON file
func (l *Logger) LogRequest(r *http.Request, statusCode int, duration time.Duration, contentLength int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Extract query parameters
	queryParams := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			queryParams[key] = values[0]
		}
	}

	// Extract headers (skip sensitive ones or limit size)
	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// Read body if available (for POST, PUT, PATCH requests)
	var body string
	if r.Body != nil && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
		// Body might have been read already, so we use the saved body if available
		if bodyBytes, ok := r.Context().Value(RequestBodyKey).([]byte); ok {
			body = string(bodyBytes)
			// Limit body size in logs
			if len(body) > 10000 {
				body = body[:10000] + "... (truncated)"
			}
		}
	}

	logEntry := RequestLog{
		Timestamp:     time.Now().Format(time.RFC3339),
		Method:        r.Method,
		Path:          r.URL.Path,
		QueryParams:   queryParams,
		Headers:       headers,
		Body:          body,
		RemoteAddr:    r.RemoteAddr,
		StatusCode:    statusCode,
		ResponseTime:  duration.String(),
		ContentLength: contentLength,
	}

	if err := l.encoder.Encode(logEntry); err != nil {
		return fmt.Errorf("failed to write log entry: %w", err)
	}

	return nil
}

// Close closes the log file
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// FilePath returns the path to the log file
func (l *Logger) FilePath() string {
	return l.filePath
}

// ContextKey is a custom type for context keys
type ContextKey string

// RequestBodyKey is the context key for storing the request body
const RequestBodyKey ContextKey = "requestBody"

// BodyCapturingReader wraps an io.ReadCloser to capture the body while reading
type BodyCapturingReader struct {
	io.ReadCloser
	body []byte
}

// Read reads from the underlying reader and captures the data
func (b *BodyCapturingReader) Read(p []byte) (n int, err error) {
	n, err = b.ReadCloser.Read(p)
	if n > 0 {
		b.body = append(b.body, p[:n]...)
	}
	return n, err
}

// CapturedBody returns the captured body data
func (b *BodyCapturingReader) CapturedBody() []byte {
	return b.body
}
