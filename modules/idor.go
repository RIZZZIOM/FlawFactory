package modules

import (
	"fmt"
	"strconv"
	"strings"
)

// IDOR implements the Insecure Direct Object Reference vulnerability module
type IDOR struct{}

// init registers the module
func init() {
	Register(&IDOR{})
}

// Info returns module metadata
func (m *IDOR) Info() ModuleInfo {
	return ModuleInfo{
		Name:        "idor",
		Description: "Insecure Direct Object Reference - access control bypass via parameter manipulation",
		SupportedPlacements: []string{
			"query_param",
			"path_param",
			"form_field",
			"json_field",
			"header",
			"cookie",
		},
		RequiresSink: "sqlite",
		ValidVariants: map[string][]string{
			"variant":        {"numeric", "uuid", "encoded", "predictable"},
			"access_control": {"none", "weak_header", "weak_cookie", "role_based", "predictable_token"},
		},
	}
}

// Handle processes the request and returns data based on the provided ID
// without proper authorization checks (intentionally vulnerable)
func (m *IDOR) Handle(ctx *HandlerContext) (*Result, error) {
	if ctx.Sinks == nil || ctx.Sinks.SQLite == nil {
		return nil, fmt.Errorf("SQLite sink not available")
	}

	// Get configuration
	variant := ctx.GetConfigString("variant", "numeric")
	queryTemplate := ctx.GetConfigString("query_template", "")
	showErrors := ctx.GetConfigBool("show_errors", true)
	accessControl := ctx.GetConfigString("access_control", "none")

	if queryTemplate == "" {
		return nil, fmt.Errorf("query_template is required for idor")
	}

	// Validate input based on variant
	input := ctx.Input
	if err := m.validateInput(input, variant); err != nil {
		if showErrors {
			return &Result{
				Error: err.Error(),
				Data: map[string]interface{}{
					"error":   err.Error(),
					"blocked": true,
				},
				StatusCode: 400,
			}, nil
		}
		return NewErrorResult("Invalid input"), nil
	}

	// Apply access control simulation (intentionally weak or bypassed)
	if blocked, err := m.checkAccessControl(ctx, input, accessControl); blocked {
		if showErrors {
			return &Result{
				Error: err.Error(),
				Data: map[string]interface{}{
					"error":   err.Error(),
					"blocked": true,
				},
				StatusCode: 403,
			}, nil
		}
		return &Result{
			Data:       map[string]interface{}{"message": "Access denied"},
			StatusCode: 403,
		}, nil
	}

	// Build the query by replacing {input} with user input (vulnerable to IDOR)
	query := strings.ReplaceAll(queryTemplate, "{input}", input)

	// Execute based on variant
	switch variant {
	case "numeric":
		return m.handleNumeric(ctx, query, showErrors)
	case "uuid":
		return m.handleUUID(ctx, query, showErrors)
	case "encoded":
		return m.handleEncoded(ctx, query, showErrors, input)
	case "predictable":
		return m.handlePredictable(ctx, query, showErrors, input)
	default:
		return m.handleNumeric(ctx, query, showErrors)
	}
}

// validateInput validates the input based on the variant
func (m *IDOR) validateInput(input string, variant string) error {
	if input == "" {
		return fmt.Errorf("ID parameter is required")
	}

	switch variant {
	case "numeric":
		// Must be a valid integer
		if _, err := strconv.Atoi(input); err != nil {
			return fmt.Errorf("ID must be a numeric value")
		}
	case "uuid":
		// Basic UUID format check (not strict)
		if len(input) < 8 {
			return fmt.Errorf("ID must be a valid UUID")
		}
	case "encoded":
		// Accept any encoded value
		if len(input) < 1 {
			return fmt.Errorf("ID cannot be empty")
		}
	case "predictable":
		// Accept any pattern-based value
		if len(input) < 1 {
			return fmt.Errorf("ID cannot be empty")
		}
	}

	return nil
}

// checkAccessControl simulates various (weak) access control mechanisms
func (m *IDOR) checkAccessControl(ctx *HandlerContext, input string, accessControl string) (bool, error) {
	switch accessControl {
	case "none":
		// No access control - fully vulnerable
		return false, nil

	case "weak_header":
		// Check for a header that can be easily spoofed
		authHeader := ctx.Request.Header.Get("X-User-ID")
		if authHeader == "" {
			return true, fmt.Errorf("unauthorized: missing X-User-ID header")
		}
		// Still vulnerable - doesn't verify if user owns the resource
		return false, nil

	case "weak_cookie":
		// Check for a cookie that can be manipulated
		cookie, err := ctx.Request.Cookie("user_id")
		if err != nil || cookie.Value == "" {
			return true, fmt.Errorf("unauthorized: missing user_id cookie")
		}
		// Still vulnerable - doesn't verify ownership
		return false, nil

	case "role_based":
		// Check for role header but allow admin bypass
		roleHeader := ctx.Request.Header.Get("X-User-Role")
		if roleHeader == "admin" {
			return false, nil // Admin can access anything
		}
		// Regular users can still access any resource (IDOR)
		return false, nil

	case "predictable_token":
		// Token check that uses predictable patterns
		token := ctx.Request.Header.Get("Authorization")
		if token == "" {
			return true, fmt.Errorf("unauthorized: missing Authorization header")
		}
		// Token format: "Bearer user_<id>" - easily predictable
		if !strings.HasPrefix(token, "Bearer user_") {
			return true, fmt.Errorf("unauthorized: invalid token format")
		}
		return false, nil

	default:
		return false, nil
	}
}

// handleNumeric handles numeric ID-based IDOR (most common)
func (m *IDOR) handleNumeric(ctx *HandlerContext, query string, showErrors bool) (*Result, error) {
	results, err := ctx.Sinks.SQLite.Query(query)
	if err != nil {
		if showErrors {
			return &Result{
				Error: err.Error(),
				Data: map[string]interface{}{
					"query": query,
					"error": err.Error(),
				},
			}, nil
		}
		return NewErrorResult("Database error"), nil
	}

	if len(results) == 0 {
		return &Result{
			Data: map[string]interface{}{
				"message": "Resource not found",
			},
			StatusCode: 404,
		}, nil
	}

	return NewResult(map[string]interface{}{
		"resource": results[0],
		"count":    len(results),
	}), nil
}

// handleUUID handles UUID-based IDOR
func (m *IDOR) handleUUID(ctx *HandlerContext, query string, showErrors bool) (*Result, error) {
	// UUID-based resources are often thought to be "secure" but aren't
	results, err := ctx.Sinks.SQLite.Query(query)
	if err != nil {
		if showErrors {
			return &Result{
				Error: err.Error(),
				Data: map[string]interface{}{
					"error": err.Error(),
				},
			}, nil
		}
		return NewErrorResult("Database error"), nil
	}

	if len(results) == 0 {
		return &Result{
			Data: map[string]interface{}{
				"message": "Resource not found",
			},
			StatusCode: 404,
		}, nil
	}

	return NewResult(map[string]interface{}{
		"resource":      results[0],
		"resource_type": "uuid_based",
	}), nil
}

// handleEncoded handles encoded/obfuscated ID IDOR (base64, hex, etc.)
func (m *IDOR) handleEncoded(ctx *HandlerContext, query string, showErrors bool, input string) (*Result, error) {
	results, err := ctx.Sinks.SQLite.Query(query)
	if err != nil {
		if showErrors {
			return &Result{
				Error: err.Error(),
				Data: map[string]interface{}{
					"error": err.Error(),
				},
			}, nil
		}
		return NewErrorResult("Database error"), nil
	}

	if len(results) == 0 {
		return &Result{
			Data: map[string]interface{}{
				"message": "Resource not found",
			},
			StatusCode: 404,
		}, nil
	}

	return NewResult(map[string]interface{}{
		"resource":      results[0],
		"resource_type": "encoded",
		"decoded_id":    input, // Expose the decoded value for learning
	}), nil
}

// handlePredictable handles predictable pattern-based IDOR
func (m *IDOR) handlePredictable(ctx *HandlerContext, query string, showErrors bool, input string) (*Result, error) {
	results, err := ctx.Sinks.SQLite.Query(query)
	if err != nil {
		if showErrors {
			return &Result{
				Error: err.Error(),
				Data: map[string]interface{}{
					"error": err.Error(),
				},
			}, nil
		}
		return NewErrorResult("Database error"), nil
	}

	if len(results) == 0 {
		return &Result{
			Data: map[string]interface{}{
				"message": "Resource not found",
			},
			StatusCode: 404,
		}, nil
	}

	// For predictable patterns, might include helpful info for learning
	return NewResult(map[string]interface{}{
		"resource":      results[0],
		"resource_type": "predictable_pattern",
		"pattern_used":  input,
	}), nil
}
