package sinks

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTP provides outbound HTTP requests for SSRF testing
type HTTP struct {
	client    *http.Client
	userAgent string
	timeout   time.Duration
}

// NewHTTP creates a new HTTP sink with default settings
func NewHTTP() *HTTP {
	return &HTTP{
		client: &http.Client{
			Timeout: 30 * time.Second,
			// Allow redirects by default
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		userAgent: "FlawFactory/1.0",
		timeout:   30 * time.Second,
	}
}

// NewHTTPWithOptions creates an HTTP sink with custom options
func NewHTTPWithOptions(timeout time.Duration, followRedirects bool) *HTTP {
	h := &HTTP{
		client: &http.Client{
			Timeout: timeout,
		},
		userAgent: "FlawFactory/1.0",
		timeout:   timeout,
	}

	if !followRedirects {
		h.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return h
}

// Close is a no-op for the HTTP sink
func (h *HTTP) Close() error {
	return nil
}

// HTTPResponse represents the response from an HTTP request
type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Body       string            `json:"body"`
	Headers    map[string]string `json:"headers"`
}

// Fetch makes a GET request to the specified URL - intentionally vulnerable to SSRF
func (h *HTTP) Fetch(url string) (*HTTPResponse, error) {
	return h.FetchWithOptions(url, HTTPOptions{
		Method:          "GET",
		FollowRedirects: true,
		Timeout:         int(h.timeout.Seconds()),
	})
}

// HTTPOptions configures an HTTP request
type HTTPOptions struct {
	Method          string
	Headers         map[string]string
	Body            string
	FollowRedirects bool
	Timeout         int // seconds
}

// FetchWithOptions makes an HTTP request with custom options
func (h *HTTP) FetchWithOptions(url string, opts HTTPOptions) (*HTTPResponse, error) {
	// Create a client with the specified options
	client := h.client
	if opts.Timeout > 0 {
		client = &http.Client{
			Timeout: time.Duration(opts.Timeout) * time.Second,
		}

		if !opts.FollowRedirects {
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
		}
	}

	// Create request
	method := opts.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if opts.Body != "" {
		bodyReader = strings.NewReader(opts.Body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set User-Agent
	req.Header.Set("User-Agent", h.userAgent)

	// Set custom headers
	for key, value := range opts.Headers {
		req.Header.Set(key, value)
	}

	// Make the request - this is intentionally vulnerable to SSRF
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Collect headers
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Body:       string(body),
		Headers:    headers,
	}, nil
}

// FetchWithFilter makes a request with optional URL filtering
func (h *HTTP) FetchWithFilter(url string, filter string, allowedSchemes []string) (*HTTPResponse, error) {
	switch filter {
	case "scheme_only":
		// Only allow specific schemes
		if len(allowedSchemes) == 0 {
			allowedSchemes = []string{"http://", "https://"}
		}
		allowed := false
		for _, scheme := range allowedSchemes {
			if strings.HasPrefix(strings.ToLower(url), scheme) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("URL scheme not allowed")
		}

	case "basic_host":
		// Block localhost and internal IPs (basic filter, easily bypassed)
		lowerURL := strings.ToLower(url)
		blockedPatterns := []string{
			"localhost",
			"127.0.0.1",
			"0.0.0.0",
			"[::1]",
			"169.254.",
			"10.",
			"192.168.",
			"172.16.", "172.17.", "172.18.", "172.19.",
			"172.20.", "172.21.", "172.22.", "172.23.",
			"172.24.", "172.25.", "172.26.", "172.27.",
			"172.28.", "172.29.", "172.30.", "172.31.",
		}
		for _, pattern := range blockedPatterns {
			if strings.Contains(lowerURL, pattern) {
				return nil, fmt.Errorf("access to internal hosts is not allowed")
			}
		}

	case "none":
		// No filtering - fully vulnerable
	}

	return h.Fetch(url)
}

// SetUserAgent changes the User-Agent header
func (h *HTTP) SetUserAgent(userAgent string) {
	h.userAgent = userAgent
}
