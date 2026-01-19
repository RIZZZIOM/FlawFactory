package builder

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/RIZZZIOM/FlawFactory/config"
	"github.com/RIZZZIOM/FlawFactory/modules"
	"github.com/RIZZZIOM/FlawFactory/server"
	"github.com/RIZZZIOM/FlawFactory/sinks"
)

// Builder constructs the server from configuration
type Builder struct {
	config      *config.Config
	sinks       *SinkManager
	logFilePath string
}

// SinkManager holds all initialized sinks
type SinkManager struct {
	sqlite     *sinks.SQLite
	filesystem *sinks.Filesystem
	command    *sinks.Command
	httpSink   *sinks.HTTP
}

// New creates a new builder for the given configuration
// logFilePath specifies where to save JSON request logs (empty string disables logging)
func New(cfg *config.Config, logFilePath string) *Builder {
	return &Builder{
		config:      cfg,
		sinks:       &SinkManager{},
		logFilePath: logFilePath,
	}
}

// Build initializes all sinks and returns a configured server
func (b *Builder) Build() (*server.Server, error) {
	// Initialize sinks based on what modules need
	if err := b.initializeSinks(); err != nil {
		return nil, fmt.Errorf("failed to initialize sinks: %w", err)
	}

	// Seed database with data from config
	if err := b.seedDatabase(); err != nil {
		return nil, fmt.Errorf("failed to seed database: %w", err)
	}

	// Create files from config
	if err := b.createFiles(); err != nil {
		return nil, fmt.Errorf("failed to create files: %w", err)
	}

	// Determine host (default to 127.0.0.1 if not specified)
	host := b.config.App.Host
	if host == "" {
		host = "127.0.0.1"
	}

	// Create the server with JSON logging and TLS config
	srv, err := server.New(host, b.config.App.Port, b.logFilePath, b.config.App.TLS)
	if err != nil {
		return nil, fmt.Errorf("failed to create server: %w", err)
	}

	// Register health endpoint
	srv.Router().HandleFunc("GET", "/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"healthy","app":"%s"}`, b.config.App.Name)
	})

	// Register endpoints from config
	for _, endpoint := range b.config.Endpoints {
		if err := b.registerEndpoint(srv, endpoint); err != nil {
			return nil, fmt.Errorf("failed to register endpoint %s: %w", endpoint.Path, err)
		}
	}

	return srv, nil
}

// initializeSinks creates the sinks needed by configured modules
func (b *Builder) initializeSinks() error {
	needsSQLite := false
	needsFilesystem := false
	needsCommand := false
	needsHTTP := false

	// Check what sinks are needed based on vulnerability types
	for _, endpoint := range b.config.Endpoints {
		for _, vuln := range endpoint.Vulnerabilities {
			switch vuln.Type {
			case "sql_injection":
				needsSQLite = true
			case "path_traversal":
				needsFilesystem = true
			case "command_injection":
				needsCommand = true
			case "ssrf":
				needsHTTP = true
			}
		}
	}

	// Also check if data section exists (implies SQLite needed)
	if b.config.Data != nil && len(b.config.Data.Tables) > 0 {
		needsSQLite = true
	}

	// Also check if files section exists
	if len(b.config.Files) > 0 {
		needsFilesystem = true
	}

	// Initialize required sinks
	var err error

	if needsSQLite {
		b.sinks.sqlite, err = sinks.NewSQLite()
		if err != nil {
			return fmt.Errorf("failed to create SQLite sink: %w", err)
		}
		log.Println("Initialized SQLite sink (in-memory)")
	}

	if needsFilesystem {
		b.sinks.filesystem, err = sinks.NewFilesystem()
		if err != nil {
			return fmt.Errorf("failed to create filesystem sink: %w", err)
		}
		log.Printf("Initialized filesystem sink at %s", b.sinks.filesystem.BasePath())
	}

	if needsCommand {
		b.sinks.command = sinks.NewCommand()
		log.Println("Initialized command sink")
	}

	if needsHTTP {
		b.sinks.httpSink = sinks.NewHTTP()
		log.Println("Initialized HTTP sink")
	}

	return nil
}

// seedDatabase populates the database with data from config
func (b *Builder) seedDatabase() error {
	if b.config.Data == nil || b.sinks.sqlite == nil {
		return nil
	}

	for tableName, table := range b.config.Data.Tables {
		if err := b.sinks.sqlite.SeedTable(tableName, table.Columns, table.Rows); err != nil {
			return fmt.Errorf("failed to seed table %s: %w", tableName, err)
		}
		log.Printf("Seeded table '%s' with %d rows", tableName, len(table.Rows))
	}

	return nil
}

// createFiles creates files from config
func (b *Builder) createFiles() error {
	if b.sinks.filesystem == nil || len(b.config.Files) == 0 {
		return nil
	}

	for _, file := range b.config.Files {
		if err := b.sinks.filesystem.WriteFile(file.Path, file.Content); err != nil {
			return fmt.Errorf("failed to create file %s: %w", file.Path, err)
		}
		log.Printf("Created file: %s", file.Path)
	}

	return nil
}

// registerEndpoint registers a single endpoint with the router
func (b *Builder) registerEndpoint(srv *server.Server, endpoint config.EndpointConfig) error {
	// Determine response type
	responseType := endpoint.ResponseType
	if responseType == "" {
		responseType = "json"
	}

	// Create handler
	handler := b.createHandler(endpoint, responseType)

	// Register the route
	srv.Router().HandleFunc(endpoint.Method, endpoint.Path, handler)

	return nil
}

// createHandler creates an HTTP handler for an endpoint
func (b *Builder) createHandler(endpoint config.EndpointConfig, responseType string) http.HandlerFunc {
	extractor := server.NewExtractor()
	respBuilder := server.NewResponseBuilder()

	return func(w http.ResponseWriter, r *http.Request) {
		// If no vulnerabilities, just return a simple response
		if len(endpoint.Vulnerabilities) == 0 {
			respBuilder.Send(w, responseType, map[string]interface{}{
				"message":  "Hello from FlawFactory",
				"endpoint": endpoint.Path,
			})
			return
		}

		// Process each vulnerability
		var results []server.ModuleResult

		for _, vuln := range endpoint.Vulnerabilities {
			result := b.processVulnerability(r, w, extractor, vuln)
			results = append(results, result)
		}

		// If single vulnerability, return its result directly
		if len(results) == 1 {
			result := results[0]
			statusCode := result.StatusCode
			if statusCode == 0 {
				statusCode = http.StatusOK
			}
			if result.Error != "" {
				if statusCode == http.StatusOK {
					statusCode = http.StatusInternalServerError
				}
				respBuilder.SendError(w, responseType, statusCode, result.Error, server.DebugInfo{
					Message:   result.Error,
					Module:    result.Module,
					Placement: endpoint.Vulnerabilities[0].Placement,
					Param:     result.Param,
				})
				return
			}
			respBuilder.SendWithStatus(w, responseType, statusCode, result.Data)
			return
		}

		// Multiple vulnerabilities - return combined results
		respBuilder.SendCombined(w, responseType, results)
	}
}

// processVulnerability processes a single vulnerability and returns the result
func (b *Builder) processVulnerability(r *http.Request, w http.ResponseWriter, extractor *server.Extractor, vuln config.VulnerabilityConfig) server.ModuleResult {
	result := server.ModuleResult{
		Module: vuln.Type,
		Param:  vuln.Param,
	}

	// Extract input
	input, err := extractor.Extract(r, vuln.Placement, vuln.Param)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Get the module
	module, err := modules.Get(vuln.Type)
	if err != nil {
		result.Error = fmt.Sprintf("module not found: %s", vuln.Type)
		return result
	}

	// Create handler context
	ctx := &modules.HandlerContext{
		Request:        r,
		ResponseWriter: w,
		Input:          input,
		Placement:      vuln.Placement,
		Param:          vuln.Param,
		Config:         vuln.Config,
		Sinks:          b.createSinkContext(),
	}

	// Handle the request
	moduleResult, err := module.Handle(ctx)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	if moduleResult != nil {
		// Use RawOutput for HTML responses (e.g., XSS) if available
		if moduleResult.RawOutput != nil {
			result.Data = string(moduleResult.RawOutput)
		} else {
			result.Data = moduleResult.Data
		}
		if moduleResult.Error != "" {
			result.Error = moduleResult.Error
		}
		if moduleResult.StatusCode != 0 {
			result.StatusCode = moduleResult.StatusCode
		}
	}

	return result
}

// createSinkContext creates the sink context for modules
func (b *Builder) createSinkContext() *modules.SinkContext {
	ctx := &modules.SinkContext{}

	if b.sinks.sqlite != nil {
		ctx.SQLite = &sqliteSinkAdapter{b.sinks.sqlite}
	}

	if b.sinks.filesystem != nil {
		ctx.Filesystem = &filesystemSinkAdapter{b.sinks.filesystem}
	}

	if b.sinks.command != nil {
		ctx.Command = &commandSinkAdapter{b.sinks.command}
	}

	if b.sinks.httpSink != nil {
		ctx.HTTP = &httpSinkAdapter{b.sinks.httpSink}
	}

	return ctx
}

// Close releases all sink resources
func (b *Builder) Close() error {
	var errs []string

	if b.sinks.sqlite != nil {
		if err := b.sinks.sqlite.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("sqlite: %v", err))
		}
	}

	if b.sinks.filesystem != nil {
		if err := b.sinks.filesystem.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("filesystem: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing sinks: %s", strings.Join(errs, "; "))
	}

	return nil
}

// Sink adapters to implement the module interfaces

type sqliteSinkAdapter struct {
	sink *sinks.SQLite
}

func (a *sqliteSinkAdapter) Query(query string) ([]map[string]interface{}, error) {
	return a.sink.Query(query)
}

func (a *sqliteSinkAdapter) Exec(statement string) error {
	return a.sink.Exec(statement)
}

type filesystemSinkAdapter struct {
	sink *sinks.Filesystem
}

func (a *filesystemSinkAdapter) Read(path string) (string, error) {
	return a.sink.Read(path)
}

func (a *filesystemSinkAdapter) Exists(path string) bool {
	return a.sink.Exists(path)
}

func (a *filesystemSinkAdapter) BasePath() string {
	return a.sink.BasePath()
}

type commandSinkAdapter struct {
	sink *sinks.Command
}

func (a *commandSinkAdapter) Execute(command string) (string, error) {
	return a.sink.Execute(command)
}

type httpSinkAdapter struct {
	sink *sinks.HTTP
}

func (a *httpSinkAdapter) Fetch(url string) (*modules.HTTPResponse, error) {
	resp, err := a.sink.Fetch(url)
	if err != nil {
		return nil, err
	}
	return &modules.HTTPResponse{
		StatusCode: resp.StatusCode,
		Body:       resp.Body,
		Headers:    resp.Headers,
	}, nil
}

func (a *httpSinkAdapter) FetchWithOptions(url string, opts modules.HTTPOptions) (*modules.HTTPResponse, error) {
	sinkOpts := sinks.HTTPOptions{
		Method:          opts.Method,
		Headers:         opts.Headers,
		Body:            opts.Body,
		FollowRedirects: opts.FollowRedirects,
		Timeout:         opts.Timeout,
	}
	resp, err := a.sink.FetchWithOptions(url, sinkOpts)
	if err != nil {
		return nil, err
	}
	return &modules.HTTPResponse{
		StatusCode: resp.StatusCode,
		Body:       resp.Body,
		Headers:    resp.Headers,
	}, nil
}

// GetFilesystemWithFilter returns the filesystem sink with filter support
func (b *Builder) GetFilesystemWithFilter() *sinks.Filesystem {
	return b.sinks.filesystem
}

// Timeout helper
func getTimeoutFromConfig(cfg map[string]interface{}) time.Duration {
	if cfg == nil {
		return 30 * time.Second
	}
	if timeout, ok := cfg["timeout"]; ok {
		switch v := timeout.(type) {
		case int:
			return time.Duration(v) * time.Second
		case float64:
			return time.Duration(v) * time.Second
		}
	}
	return 30 * time.Second
}
