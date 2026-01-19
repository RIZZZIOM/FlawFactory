package modules

import (
	"fmt"
	"path/filepath"
	"strings"
)

// PathTraversal implements the path_traversal vulnerability module
type PathTraversal struct{}

// init registers the module
func init() {
	Register(&PathTraversal{})
}

// Info returns module metadata
func (m *PathTraversal) Info() ModuleInfo {
	return ModuleInfo{
		Name:        "path_traversal",
		Description: "Path Traversal vulnerability for reading arbitrary files",
		SupportedPlacements: []string{
			"query_param",
			"path_param",
			"form_field",
			"json_field",
			"multipart-form",
		},
		RequiresSink: "filesystem",
		ValidVariants: map[string][]string{
			"filter": {"none", "basic_dots", "basic_slashes", "null_byte", "url_decode"},
		},
	}
}

// Handle processes the request and reads files
func (m *PathTraversal) Handle(ctx *HandlerContext) (*Result, error) {
	if ctx.Sinks == nil || ctx.Sinks.Filesystem == nil {
		return nil, fmt.Errorf("Filesystem sink not available")
	}

	// Get configuration
	basePath := ctx.GetConfigString("base_path", "")
	filter := ctx.GetConfigString("filter", "none")
	appendExtension := ctx.GetConfigString("append_extension", "")

	// Build the file path
	filePath := ctx.Input

	// Apply filter
	filePath = applyPathFilter(filePath, filter)

	// Prepend base path if configured
	if basePath != "" {
		filePath = filepath.Join(basePath, filePath)
	}

	// Append extension if configured
	if appendExtension != "" {
		filePath = filePath + appendExtension
	}

	// Attempt to read the file
	content, err := ctx.Sinks.Filesystem.Read(filePath)
	if err != nil {
		return &Result{
			Error: err.Error(),
			Data: map[string]interface{}{
				"requested_path": ctx.Input,
				"resolved_path":  filePath,
				"error":          err.Error(),
			},
		}, nil
	}

	return NewResult(map[string]interface{}{
		"content":        content,
		"requested_path": ctx.Input,
		"resolved_path":  filePath,
		"size":           len(content),
	}), nil
}

// applyPathFilter applies path filtering based on configuration
func applyPathFilter(path, filter string) string {
	switch filter {
	case "none":
		// No filtering - fully vulnerable
		return path
	case "basic_dots":
		// Basic filter that removes "../" sequences (bypassed with nested sequences like "....//")
		// "....//etc/passwd" → removes "../" at pos 2-4 → "../etc/passwd" (still has traversal!)
		return strings.ReplaceAll(path, "../", "")
	case "basic_slashes":
		// Basic filter that normalizes slashes (dots still work)
		path = strings.ReplaceAll(path, "\\", "/")
		path = strings.ReplaceAll(path, "//", "/")
		return path
	case "null_byte":
		// Remove null bytes (historic bypass for extension append)
		return strings.ReplaceAll(path, "\x00", "")
	case "url_decode":
		// URL decode the path then remove traversal (bypass with double encoding)
		// Double encoded: %252e%252e%252f → first decode by server → %2e%2e%2f → decoded here → ../
		path = strings.ReplaceAll(path, "%2e", ".")
		path = strings.ReplaceAll(path, "%2E", ".")
		path = strings.ReplaceAll(path, "%2f", "/")
		path = strings.ReplaceAll(path, "%2F", "/")
		path = strings.ReplaceAll(path, "%5c", "\\")
		path = strings.ReplaceAll(path, "%5C", "\\")
		return path
	default:
		return path
	}
}
