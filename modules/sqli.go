package modules

import (
	"fmt"
	"strings"
)

// SQLInjection implements the sql_injection vulnerability module
type SQLInjection struct{}

// init registers the module
func init() {
	Register(&SQLInjection{})
}

// Info returns module metadata
func (m *SQLInjection) Info() ModuleInfo {
	return ModuleInfo{
		Name:        "sql_injection",
		Description: "SQL Injection vulnerability with multiple variants (error_based, blind_boolean)",
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
			"variant": {"error_based", "blind_boolean"},
		},
	}
}

// Handle processes the request and executes SQL
func (m *SQLInjection) Handle(ctx *HandlerContext) (*Result, error) {
	if ctx.Sinks == nil || ctx.Sinks.SQLite == nil {
		return nil, fmt.Errorf("SQLite sink not available")
	}

	// Get configuration
	variant := ctx.GetConfigString("variant", "error_based")
	queryTemplate := ctx.GetConfigString("query_template", "")
	showErrors := ctx.GetConfigBool("show_errors", true)

	if queryTemplate == "" {
		return nil, fmt.Errorf("query_template is required for sql_injection")
	}

	// Apply any configured filter to the INPUT first (before substitution)
	filter := ctx.GetConfigString("filter", "none")
	filteredInput := applyInputFilter(ctx.Input, filter)

	// Build the query by replacing {input} with filtered user input
	query := strings.ReplaceAll(queryTemplate, "{input}", filteredInput)

	// Execute based on variant
	switch variant {
	case "error_based":
		return m.handleErrorBased(ctx, query, showErrors)
	case "blind_boolean":
		return m.handleBlindBoolean(ctx, query)
	default:
		return m.handleErrorBased(ctx, query, showErrors)
	}
}

// handleErrorBased executes SQL and returns results or errors
func (m *SQLInjection) handleErrorBased(ctx *HandlerContext, query string, showErrors bool) (*Result, error) {
	results, err := ctx.Sinks.SQLite.Query(query)
	if err != nil {
		if showErrors {
			// Return the SQL error in the response (useful for error-based injection)
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
		return NewResult(map[string]interface{}{
			"message": "No results found",
			"count":   0,
		}), nil
	}

	return NewResult(map[string]interface{}{
		"results": results,
		"count":   len(results),
	}), nil
}

// handleBlindBoolean executes SQL and returns only success/failure indicator
func (m *SQLInjection) handleBlindBoolean(ctx *HandlerContext, query string) (*Result, error) {
	results, err := ctx.Sinks.SQLite.Query(query)
	if err != nil {
		// Query failed - return generic error
		return NewResult(map[string]interface{}{
			"success": false,
			"message": "Query failed",
		}), nil
	}

	// Return only whether results were found
	found := len(results) > 0
	return NewResult(map[string]interface{}{
		"success": found,
		"message": func() string {
			if found {
				return "Record found"
			}
			return "Record not found"
		}(),
	}), nil
}

// applyInputFilter applies input filtering based on configuration
// This filters the user input BEFORE it's substituted into the query template
func applyInputFilter(input string, filter string) string {
	switch filter {
	case "basic_quotes":
		// Basic filter that escapes single quotes (easily bypassed)
		return strings.ReplaceAll(input, "'", "''")
	case "remove_comments":
		// Remove SQL comments
		input = strings.ReplaceAll(input, "--", "")
		input = strings.ReplaceAll(input, "/*", "")
		input = strings.ReplaceAll(input, "*/", "")
		return input
	case "remove_union":
		// Remove UNION keyword (case-insensitive, but easily bypassed)
		return strings.ReplaceAll(strings.ToUpper(input), "UNION", "")
	case "none":
		return input
	default:
		return input
	}
}
