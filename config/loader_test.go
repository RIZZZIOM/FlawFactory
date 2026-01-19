package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoad_ValidConfig tests loading a valid config file
func TestLoad_ValidConfig(t *testing.T) {
	// Create a temporary config file
	content := `
app:
  name: "Test App"
  description: "A test application"
  port: 8080

endpoints:
  - path: /test
    method: GET
    response_type: json
    vulnerabilities: []
`
	tmpFile := createTempYAML(t, content)
	defer os.Remove(tmpFile)

	// Load the config
	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify the loaded config
	if cfg.App.Name != "Test App" {
		t.Errorf("Expected app name 'Test App', got '%s'", cfg.App.Name)
	}

	if cfg.App.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", cfg.App.Port)
	}

	if len(cfg.Endpoints) != 1 {
		t.Errorf("Expected 1 endpoint, got %d", len(cfg.Endpoints))
	}

	if cfg.Endpoints[0].Path != "/test" {
		t.Errorf("Expected endpoint path '/test', got '%s'", cfg.Endpoints[0].Path)
	}
}

// TestLoad_WithData tests loading config with database tables
func TestLoad_WithData(t *testing.T) {
	content := `
app:
  name: "DB Test"
  port: 8080

data:
  tables:
    users:
      columns: [id, username, password]
      rows:
        - [1, "admin", "secret"]
        - [2, "user", "pass"]

endpoints:
  - path: /users
    method: GET
    response_type: json
    vulnerabilities: []
`
	tmpFile := createTempYAML(t, content)
	defer os.Remove(tmpFile)

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify data section
	if cfg.Data == nil {
		t.Fatal("Expected data section to be present")
	}

	usersTable, exists := cfg.Data.Tables["users"]
	if !exists {
		t.Fatal("Expected 'users' table to exist")
	}

	if len(usersTable.Columns) != 3 {
		t.Errorf("Expected 3 columns, got %d", len(usersTable.Columns))
	}

	if len(usersTable.Rows) != 2 {
		t.Errorf("Expected 2 rows, got %d", len(usersTable.Rows))
	}
}

// TestLoad_WithFiles tests loading config with file definitions
func TestLoad_WithFiles(t *testing.T) {
	content := `
app:
  name: "File Test"
  port: 8080

files:
  - path: /etc/passwd
    content: "root:x:0:0:root:/root:/bin/bash"
  - path: /app/config.ini
    content: "[database]\nhost=localhost"

endpoints:
  - path: /file
    method: GET
    response_type: text
    vulnerabilities: []
`
	tmpFile := createTempYAML(t, content)
	defer os.Remove(tmpFile)

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(cfg.Files) != 2 {
		t.Errorf("Expected 2 files, got %d", len(cfg.Files))
	}

	if cfg.Files[0].Path != "/etc/passwd" {
		t.Errorf("Expected file path '/etc/passwd', got '%s'", cfg.Files[0].Path)
	}
}

// TestLoad_WithVulnerabilities tests loading endpoints with vulnerabilities
func TestLoad_WithVulnerabilities(t *testing.T) {
	content := `
app:
  name: "Vuln Test"
  port: 8080

endpoints:
  - path: /search
    method: GET
    response_type: json
    vulnerabilities:
      - type: sql_injection
        placement: query_param
        param: id
        config:
          variant: error_based
          query_template: "SELECT * FROM users WHERE id = {input}"
      - type: xss_reflected
        placement: query_param
        param: q
        config:
          context: body
`
	tmpFile := createTempYAML(t, content)
	defer os.Remove(tmpFile)

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	endpoint := cfg.Endpoints[0]
	if len(endpoint.Vulnerabilities) != 2 {
		t.Errorf("Expected 2 vulnerabilities, got %d", len(endpoint.Vulnerabilities))
	}

	vuln1 := endpoint.Vulnerabilities[0]
	if vuln1.Type != "sql_injection" {
		t.Errorf("Expected type 'sql_injection', got '%s'", vuln1.Type)
	}
	if vuln1.Placement != "query_param" {
		t.Errorf("Expected placement 'query_param', got '%s'", vuln1.Placement)
	}
	if vuln1.Param != "id" {
		t.Errorf("Expected param 'id', got '%s'", vuln1.Param)
	}

	// Check config map
	if vuln1.Config["variant"] != "error_based" {
		t.Errorf("Expected variant 'error_based', got '%v'", vuln1.Config["variant"])
	}
}

// TestLoad_FileNotFound tests error handling for missing file
func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

// TestLoad_InvalidYAML tests error handling for malformed YAML
func TestLoad_InvalidYAML(t *testing.T) {
	content := `
app:
  name: "Test"
  port: not_a_number
`
	tmpFile := createTempYAML(t, content)
	defer os.Remove(tmpFile)

	_, err := Load(tmpFile)
	if err == nil {
		t.Error("Expected error for invalid YAML, got nil")
	}
}

// TestLoad_EmptyFile tests error handling for empty file
func TestLoad_EmptyFile(t *testing.T) {
	tmpFile := createTempYAML(t, "")
	defer os.Remove(tmpFile)

	_, err := Load(tmpFile)
	// Empty config should fail validation (missing required fields)
	if err == nil {
		t.Error("Expected validation error for empty file, got nil")
	}
}

// Helper function to create a temporary YAML file
func createTempYAML(t *testing.T, content string) string {
	t.Helper() // Marks this as a test helper function

	tmpDir := t.TempDir() // Creates a temp directory that's automatically cleaned up
	tmpFile := filepath.Join(tmpDir, "test-config.yaml")

	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	return tmpFile
}
