package builder

import (
	"testing"

	"github.com/RIZZZIOM/FlawFactory/config"
)

// TestNew tests builder creation
func TestNew(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "test",
			Port: 8080,
		},
		Endpoints: []config.EndpointConfig{},
	}

	builder := New(cfg, "")
	if builder == nil {
		t.Fatal("Expected builder, got nil")
	}
}

// TestSinkManager tests SinkManager struct
func TestSinkManager(t *testing.T) {
	sm := &SinkManager{}

	// All sinks should be nil initially
	if sm.sqlite != nil {
		t.Error("Expected nil sqlite")
	}
	if sm.filesystem != nil {
		t.Error("Expected nil filesystem")
	}
	if sm.command != nil {
		t.Error("Expected nil command")
	}
	if sm.httpSink != nil {
		t.Error("Expected nil httpSink")
	}
}

// TestBuilder_Build_BasicConfig tests building with basic config
func TestBuilder_Build_BasicConfig(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "test-app",
			Port: 8080,
		},
		Endpoints: []config.EndpointConfig{},
	}

	builder := New(cfg, "")
	srv, err := builder.Build()
	if err != nil {
		t.Fatalf("Failed to build: %v", err)
	}

	if srv == nil {
		t.Fatal("Expected server, got nil")
	}
}

// TestBuilder_Build_WithDatabase tests building with database config
func TestBuilder_Build_WithDatabase(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "test-app",
			Port: 8080,
		},
		Data: &config.DataConfig{
			Tables: map[string]config.TableConfig{
				"users": {
					Columns: []string{"id", "name"},
					Rows: [][]interface{}{
						{"1", "alice"},
						{"2", "bob"},
					},
				},
			},
		},
		Endpoints: []config.EndpointConfig{},
	}

	builder := New(cfg, "")
	srv, err := builder.Build()
	if err != nil {
		t.Fatalf("Failed to build: %v", err)
	}

	if srv == nil {
		t.Fatal("Expected server, got nil")
	}

	// SQLite sink should be initialized
	if builder.sinks.sqlite == nil {
		t.Error("Expected SQLite sink to be initialized")
	}
}

// TestBuilder_Build_WithFiles tests building with file config
func TestBuilder_Build_WithFiles(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "test-app",
			Port: 8080,
		},
		Files: []config.FileConfig{
			{Path: "test.txt", Content: "test content"},
		},
		Endpoints: []config.EndpointConfig{},
	}

	builder := New(cfg, "")
	srv, err := builder.Build()
	if err != nil {
		t.Fatalf("Failed to build: %v", err)
	}

	if srv == nil {
		t.Fatal("Expected server, got nil")
	}

	// Filesystem sink should be initialized
	if builder.sinks.filesystem == nil {
		t.Error("Expected filesystem sink to be initialized")
	}

	// Cleanup
	if builder.sinks.filesystem != nil {
		builder.sinks.filesystem.Close()
	}
}

// TestBuilder_Build_WithSQLInjection tests building with SQL injection endpoint
func TestBuilder_Build_WithSQLInjection(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "test-app",
			Port: 8080,
		},
		Data: &config.DataConfig{
			Tables: map[string]config.TableConfig{
				"users": {
					Columns: []string{"id", "name"},
					Rows:    [][]interface{}{{"1", "admin"}},
				},
			},
		},
		Endpoints: []config.EndpointConfig{
			{
				Path:   "/users",
				Method: "GET",
				Vulnerabilities: []config.VulnerabilityConfig{
					{
						Type:      "sql_injection",
						Param:     "id",
						Placement: "query_param",
					},
				},
			},
		},
	}

	builder := New(cfg, "")
	srv, err := builder.Build()
	if err != nil {
		t.Fatalf("Failed to build: %v", err)
	}

	if srv == nil {
		t.Fatal("Expected server, got nil")
	}

	// SQLite sink should be initialized
	if builder.sinks.sqlite == nil {
		t.Error("Expected SQLite sink to be initialized for SQL injection")
	}
}

// TestBuilder_Build_WithPathTraversal tests building with path traversal endpoint
func TestBuilder_Build_WithPathTraversal(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "test-app",
			Port: 8080,
		},
		Endpoints: []config.EndpointConfig{
			{
				Path:   "/files",
				Method: "GET",
				Vulnerabilities: []config.VulnerabilityConfig{
					{
						Type:      "path_traversal",
						Param:     "file",
						Placement: "query_param",
					},
				},
			},
		},
	}

	builder := New(cfg, "")
	srv, err := builder.Build()
	if err != nil {
		t.Fatalf("Failed to build: %v", err)
	}

	if srv == nil {
		t.Fatal("Expected server, got nil")
	}

	// Filesystem sink should be initialized
	if builder.sinks.filesystem == nil {
		t.Error("Expected filesystem sink to be initialized for path traversal")
	}

	// Cleanup
	if builder.sinks.filesystem != nil {
		builder.sinks.filesystem.Close()
	}
}

// TestBuilder_Build_WithCommandInjection tests building with command injection endpoint
func TestBuilder_Build_WithCommandInjection(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "test-app",
			Port: 8080,
		},
		Endpoints: []config.EndpointConfig{
			{
				Path:   "/ping",
				Method: "GET",
				Vulnerabilities: []config.VulnerabilityConfig{
					{
						Type:      "command_injection",
						Param:     "host",
						Placement: "query_param",
					},
				},
			},
		},
	}

	builder := New(cfg, "")
	srv, err := builder.Build()
	if err != nil {
		t.Fatalf("Failed to build: %v", err)
	}

	if srv == nil {
		t.Fatal("Expected server, got nil")
	}

	// Command sink should be initialized
	if builder.sinks.command == nil {
		t.Error("Expected command sink to be initialized for command injection")
	}
}

// TestBuilder_Build_WithSSRF tests building with SSRF endpoint
func TestBuilder_Build_WithSSRF(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "test-app",
			Port: 8080,
		},
		Endpoints: []config.EndpointConfig{
			{
				Path:   "/fetch",
				Method: "GET",
				Vulnerabilities: []config.VulnerabilityConfig{
					{
						Type:      "ssrf",
						Param:     "url",
						Placement: "query_param",
					},
				},
			},
		},
	}

	builder := New(cfg, "")
	srv, err := builder.Build()
	if err != nil {
		t.Fatalf("Failed to build: %v", err)
	}

	if srv == nil {
		t.Fatal("Expected server, got nil")
	}

	// HTTP sink should be initialized
	if builder.sinks.httpSink == nil {
		t.Error("Expected HTTP sink to be initialized for SSRF")
	}
}

// TestBuilder_Build_MultipleSinks tests multiple sinks initialized together
func TestBuilder_Build_MultipleSinks(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "test-app",
			Port: 8080,
		},
		Data: &config.DataConfig{
			Tables: map[string]config.TableConfig{
				"test": {
					Columns: []string{"id"},
					Rows:    [][]interface{}{{"1"}},
				},
			},
		},
		Files: []config.FileConfig{
			{Path: "test.txt", Content: "test"},
		},
		Endpoints: []config.EndpointConfig{
			{
				Path:   "/cmd",
				Method: "GET",
				Vulnerabilities: []config.VulnerabilityConfig{
					{Type: "command_injection", Param: "cmd", Placement: "query_param"},
				},
			},
			{
				Path:   "/fetch",
				Method: "GET",
				Vulnerabilities: []config.VulnerabilityConfig{
					{Type: "ssrf", Param: "url", Placement: "query_param"},
				},
			},
		},
	}

	builder := New(cfg, "")
	srv, err := builder.Build()
	if err != nil {
		t.Fatalf("Failed to build: %v", err)
	}

	if srv == nil {
		t.Fatal("Expected server, got nil")
	}

	if builder.sinks.sqlite == nil {
		t.Error("Expected SQLite sink")
	}
	if builder.sinks.filesystem == nil {
		t.Error("Expected Filesystem sink")
	}
	if builder.sinks.command == nil {
		t.Error("Expected Command sink")
	}
	if builder.sinks.httpSink == nil {
		t.Error("Expected HTTP sink")
	}

	// Cleanup
	if builder.sinks.filesystem != nil {
		builder.sinks.filesystem.Close()
	}
}
