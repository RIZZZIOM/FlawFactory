package modules

import (
	"net/http"
)

// Module defines the interface that all vulnerability modules must implement
type Module interface {
	// Info returns metadata about the module
	Info() ModuleInfo

	// Handle processes a request and returns the result
	Handle(ctx *HandlerContext) (*Result, error)
}

// ModuleInfo contains metadata about a vulnerability module
type ModuleInfo struct {
	// Name is the unique identifier for this module (e.g., "sql_injection")
	Name string

	// Description is a human-readable description
	Description string

	// SupportedPlacements lists where this module can extract input from
	SupportedPlacements []string

	// RequiresSink indicates what type of sink this module needs (empty if none)
	RequiresSink string

	// ValidVariants maps config keys to their valid values (e.g., "variant" -> ["error_based", "blind_boolean"])
	// Used for validation warnings when invalid values are provided
	ValidVariants map[string][]string
}

// HandlerContext provides all the context needed by a module to handle a request
type HandlerContext struct {
	// Request is the original HTTP request
	Request *http.Request

	// ResponseWriter for sending responses (typically not used directly)
	ResponseWriter http.ResponseWriter

	// Input is the extracted user input
	Input string

	// Placement is where the input was extracted from
	Placement string

	// Param is the parameter name
	Param string

	// Config holds module-specific configuration from YAML
	Config map[string]interface{}

	// Sinks provides access to the available sinks
	Sinks *SinkContext
}

// SinkContext holds references to available sinks
type SinkContext struct {
	// SQLite provides database operations
	SQLite SQLiteSink

	// Filesystem provides file operations
	Filesystem FilesystemSink

	// Command provides command execution
	Command CommandSink

	// HTTP provides outbound HTTP requests
	HTTP HTTPSink
}

// SQLiteSink interface for database operations
type SQLiteSink interface {
	// Query executes a SQL query and returns results
	Query(query string) ([]map[string]interface{}, error)

	// Exec executes a SQL statement
	Exec(statement string) error
}

// FilesystemSink interface for file operations
type FilesystemSink interface {
	// Read reads a file and returns its contents
	Read(path string) (string, error)

	// Exists checks if a file exists
	Exists(path string) bool

	// BasePath returns the base directory for file operations
	BasePath() string
}

// CommandSink interface for command execution
type CommandSink interface {
	// Execute runs a command and returns output
	Execute(command string) (string, error)
}

// HTTPSink interface for outbound HTTP requests
type HTTPSink interface {
	// Fetch makes an HTTP GET request and returns the response
	Fetch(url string) (*HTTPResponse, error)

	// FetchWithOptions makes an HTTP request with options
	FetchWithOptions(url string, opts HTTPOptions) (*HTTPResponse, error)
}

// HTTPResponse represents the response from an HTTP request
type HTTPResponse struct {
	StatusCode int
	Body       string
	Headers    map[string]string
}

// HTTPOptions configures an HTTP request
type HTTPOptions struct {
	Method          string
	Headers         map[string]string
	Body            string
	FollowRedirects bool
	Timeout         int // in seconds
}

// Result holds the output from a module handler
type Result struct {
	// Data is the primary output (query results, file contents, command output, etc.)
	Data interface{}

	// Error is set if the module encountered an error (may be intentionally exposed)
	Error string

	// RawOutput is for modules that want to control output directly
	RawOutput []byte

	// StatusCode overrides the default HTTP status code
	StatusCode int

	// Headers are additional headers to set on the response
	Headers map[string]string
}

// NewResult creates a new result with data
func NewResult(data interface{}) *Result {
	return &Result{Data: data}
}

// NewErrorResult creates a new result with an error
func NewErrorResult(err string) *Result {
	return &Result{Error: err}
}

// GetConfigString safely gets a string from the config map
func (ctx *HandlerContext) GetConfigString(key string, defaultValue string) string {
	if ctx.Config == nil {
		return defaultValue
	}
	if val, ok := ctx.Config[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultValue
}

// GetConfigBool safely gets a bool from the config map
func (ctx *HandlerContext) GetConfigBool(key string, defaultValue bool) bool {
	if ctx.Config == nil {
		return defaultValue
	}
	if val, ok := ctx.Config[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultValue
}

// GetConfigInt safely gets an int from the config map
func (ctx *HandlerContext) GetConfigInt(key string, defaultValue int) int {
	if ctx.Config == nil {
		return defaultValue
	}
	if val, ok := ctx.Config[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return defaultValue
}
