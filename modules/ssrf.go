package modules

import (
	"fmt"
	"strings"
)

// SSRF implements the ssrf vulnerability module
type SSRF struct{}

// init registers the module
func init() {
	Register(&SSRF{})
}

// Info returns module metadata
func (m *SSRF) Info() ModuleInfo {
	return ModuleInfo{
		Name:        "ssrf",
		Description: "Server-Side Request Forgery vulnerability for making arbitrary HTTP requests",
		SupportedPlacements: []string{
			"query_param",
			"form_field",
			"json_field",
			"header",
		},
		RequiresSink: "http",
		ValidVariants: map[string][]string{
			"filter": {"none", "scheme_only", "basic_host"},
		},
	}
}

// Handle processes the request and makes outbound HTTP requests
func (m *SSRF) Handle(ctx *HandlerContext) (*Result, error) {
	if ctx.Sinks == nil || ctx.Sinks.HTTP == nil {
		return nil, fmt.Errorf("HTTP sink not available")
	}

	// Get configuration
	filter := ctx.GetConfigString("filter", "none")
	followRedirects := ctx.GetConfigBool("follow_redirects", true)
	timeout := ctx.GetConfigInt("timeout", 30)
	returnBody := ctx.GetConfigBool("return_body", true)

	url := ctx.Input

	// Apply URL filter
	if err := validateURL(url, filter, ctx.Config); err != nil {
		return &Result{
			Error: err.Error(),
			Data: map[string]interface{}{
				"url":     url,
				"error":   err.Error(),
				"blocked": true,
			},
		}, nil
	}

	// Make the request
	opts := HTTPOptions{
		Method:          "GET",
		FollowRedirects: followRedirects,
		Timeout:         timeout,
	}

	resp, err := ctx.Sinks.HTTP.FetchWithOptions(url, opts)
	if err != nil {
		return &Result{
			Error: err.Error(),
			Data: map[string]interface{}{
				"url":   url,
				"error": err.Error(),
			},
		}, nil
	}

	// Build response data
	data := map[string]interface{}{
		"url":         url,
		"status_code": resp.StatusCode,
		"headers":     resp.Headers,
	}

	if returnBody {
		// Truncate body if too large
		body := resp.Body
		if len(body) > 10000 {
			body = body[:10000] + "\n...(truncated)"
		}
		data["body"] = body
		data["body_length"] = len(resp.Body)
	}

	return NewResult(data), nil
}

// validateURL validates the URL based on the filter configuration
func validateURL(url, filter string, cfg map[string]interface{}) error {
	switch filter {
	case "none":
		// No filtering - fully vulnerable
		return nil

	case "scheme_only":
		// Only allow specific schemes
		allowedSchemes := getStringSlice(cfg, "allowed_schemes", []string{"http://", "https://"})
		allowed := false
		lowerURL := strings.ToLower(url)
		for _, scheme := range allowedSchemes {
			if strings.HasPrefix(lowerURL, strings.ToLower(scheme)) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("URL scheme not allowed. Allowed schemes: %v", allowedSchemes)
		}
		return nil

	case "basic_host":
		// Block localhost and internal IPs (basic filter, easily bypassed)
		lowerURL := strings.ToLower(url)
		blockedPatterns := []string{
			"localhost",
			"127.0.0.1",
			"127.0.0.0",
			"0.0.0.0",
			"[::1]",
			"[0:0:0:0:0:0:0:1]",
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
				return fmt.Errorf("access to internal hosts is not allowed")
			}
		}
		return nil

	default:
		return nil
	}
}

// getStringSlice safely gets a string slice from config
func getStringSlice(cfg map[string]interface{}, key string, defaultValue []string) []string {
	if cfg == nil {
		return defaultValue
	}
	if val, ok := cfg[key]; ok {
		switch v := val.(type) {
		case []string:
			return v
		case []interface{}:
			result := make([]string, 0, len(v))
			for _, item := range v {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			if len(result) > 0 {
				return result
			}
		}
	}
	return defaultValue
}
