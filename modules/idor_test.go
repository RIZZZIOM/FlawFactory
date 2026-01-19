package modules

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// MockSQLiteSink is a mock implementation of SQLiteSink for testing IDOR
type MockSQLiteSinkIDOR struct {
	QueryFunc func(query string) ([]map[string]interface{}, error)
	ExecFunc  func(statement string) error
}

func (m *MockSQLiteSinkIDOR) Query(query string) ([]map[string]interface{}, error) {
	if m.QueryFunc != nil {
		return m.QueryFunc(query)
	}
	return nil, nil
}

func (m *MockSQLiteSinkIDOR) Exec(statement string) error {
	if m.ExecFunc != nil {
		return m.ExecFunc(statement)
	}
	return nil
}

// TestIDOR_Info tests module metadata
func TestIDOR_Info(t *testing.T) {
	m := &IDOR{}
	info := m.Info()

	if info.Name != "idor" {
		t.Errorf("Expected Name 'idor', got '%s'", info.Name)
	}

	if info.RequiresSink != "sqlite" {
		t.Errorf("Expected RequiresSink 'sqlite', got '%s'", info.RequiresSink)
	}

	expectedPlacements := []string{"query_param", "path_param", "form_field", "json_field", "header", "cookie"}
	if len(info.SupportedPlacements) != len(expectedPlacements) {
		t.Errorf("Expected %d placements, got %d", len(expectedPlacements), len(info.SupportedPlacements))
	}
}

// TestIDOR_Handle_NumericVariant tests numeric IDOR handling
func TestIDOR_Handle_NumericVariant(t *testing.T) {
	m := &IDOR{}

	mockSink := &MockSQLiteSinkIDOR{
		QueryFunc: func(query string) ([]map[string]interface{}, error) {
			// Simulate returning user data based on ID
			return []map[string]interface{}{
				{"id": 1, "username": "admin", "email": "admin@test.com"},
			}, nil
		},
	}

	ctx := &HandlerContext{
		Input:     "1",
		Placement: "query_param",
		Param:     "user_id",
		Config: map[string]interface{}{
			"variant":        "numeric",
			"query_template": "SELECT * FROM users WHERE id = {input}",
		},
		Sinks: &SinkContext{
			SQLite: mockSink,
		},
		Request: httptest.NewRequest("GET", "/user?user_id=1", nil),
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatal("Expected Data to be map[string]interface{}")
	}

	if _, ok := data["resource"]; !ok {
		t.Error("Expected 'resource' in result data")
	}
}

// TestIDOR_Handle_UUIDVariant tests UUID-based IDOR handling
func TestIDOR_Handle_UUIDVariant(t *testing.T) {
	m := &IDOR{}

	mockSink := &MockSQLiteSinkIDOR{
		QueryFunc: func(query string) ([]map[string]interface{}, error) {
			return []map[string]interface{}{
				{"id": "550e8400-e29b-41d4-a716-446655440000", "name": "Secret Document"},
			}, nil
		},
	}

	ctx := &HandlerContext{
		Input:     "550e8400-e29b-41d4-a716-446655440000",
		Placement: "path_param",
		Param:     "document_id",
		Config: map[string]interface{}{
			"variant":        "uuid",
			"query_template": "SELECT * FROM documents WHERE id = '{input}'",
		},
		Sinks: &SinkContext{
			SQLite: mockSink,
		},
		Request: httptest.NewRequest("GET", "/document/550e8400", nil),
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatal("Expected Data to be map[string]interface{}")
	}

	if data["resource_type"] != "uuid_based" {
		t.Errorf("Expected resource_type 'uuid_based', got '%v'", data["resource_type"])
	}
}

// TestIDOR_Handle_EncodedVariant tests encoded ID IDOR handling
func TestIDOR_Handle_EncodedVariant(t *testing.T) {
	m := &IDOR{}

	mockSink := &MockSQLiteSinkIDOR{
		QueryFunc: func(query string) ([]map[string]interface{}, error) {
			return []map[string]interface{}{
				{"id": "MTIz", "content": "Sensitive data"},
			}, nil
		},
	}

	ctx := &HandlerContext{
		Input:     "MTIz", // base64 encoded "123"
		Placement: "query_param",
		Param:     "resource_id",
		Config: map[string]interface{}{
			"variant":        "encoded",
			"query_template": "SELECT * FROM resources WHERE encoded_id = '{input}'",
		},
		Sinks: &SinkContext{
			SQLite: mockSink,
		},
		Request: httptest.NewRequest("GET", "/resource?resource_id=MTIz", nil),
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatal("Expected Data to be map[string]interface{}")
	}

	if data["resource_type"] != "encoded" {
		t.Errorf("Expected resource_type 'encoded', got '%v'", data["resource_type"])
	}

	if data["decoded_id"] != "MTIz" {
		t.Errorf("Expected decoded_id 'MTIz', got '%v'", data["decoded_id"])
	}
}

// TestIDOR_Handle_PredictableVariant tests predictable pattern IDOR handling
func TestIDOR_Handle_PredictableVariant(t *testing.T) {
	m := &IDOR{}

	mockSink := &MockSQLiteSinkIDOR{
		QueryFunc: func(query string) ([]map[string]interface{}, error) {
			return []map[string]interface{}{
				{"invoice_id": "INV-2024-0001", "amount": 1500.00},
			}, nil
		},
	}

	ctx := &HandlerContext{
		Input:     "INV-2024-0001",
		Placement: "query_param",
		Param:     "invoice",
		Config: map[string]interface{}{
			"variant":        "predictable",
			"query_template": "SELECT * FROM invoices WHERE invoice_id = '{input}'",
		},
		Sinks: &SinkContext{
			SQLite: mockSink,
		},
		Request: httptest.NewRequest("GET", "/invoice?invoice=INV-2024-0001", nil),
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatal("Expected Data to be map[string]interface{}")
	}

	if data["resource_type"] != "predictable_pattern" {
		t.Errorf("Expected resource_type 'predictable_pattern', got '%v'", data["resource_type"])
	}
}

// TestIDOR_Handle_NoSink tests handling when sink is not available
func TestIDOR_Handle_NoSink(t *testing.T) {
	m := &IDOR{}

	ctx := &HandlerContext{
		Input:     "1",
		Placement: "query_param",
		Param:     "id",
		Config: map[string]interface{}{
			"query_template": "SELECT * FROM users WHERE id = {input}",
		},
		Sinks:   nil,
		Request: httptest.NewRequest("GET", "/user?id=1", nil),
	}

	_, err := m.Handle(ctx)
	if err == nil {
		t.Error("Expected error when sink is nil")
	}
}

// TestIDOR_Handle_MissingQueryTemplate tests handling when query_template is missing
func TestIDOR_Handle_MissingQueryTemplate(t *testing.T) {
	m := &IDOR{}

	mockSink := &MockSQLiteSinkIDOR{}

	ctx := &HandlerContext{
		Input:     "1",
		Placement: "query_param",
		Param:     "id",
		Config:    map[string]interface{}{},
		Sinks: &SinkContext{
			SQLite: mockSink,
		},
		Request: httptest.NewRequest("GET", "/user?id=1", nil),
	}

	_, err := m.Handle(ctx)
	if err == nil {
		t.Error("Expected error when query_template is missing")
	}
}

// TestIDOR_Handle_InvalidNumericInput tests handling invalid numeric input
func TestIDOR_Handle_InvalidNumericInput(t *testing.T) {
	m := &IDOR{}

	mockSink := &MockSQLiteSinkIDOR{}

	ctx := &HandlerContext{
		Input:     "not-a-number",
		Placement: "query_param",
		Param:     "id",
		Config: map[string]interface{}{
			"variant":        "numeric",
			"query_template": "SELECT * FROM users WHERE id = {input}",
			"show_errors":    true,
		},
		Sinks: &SinkContext{
			SQLite: mockSink,
		},
		Request: httptest.NewRequest("GET", "/user?id=not-a-number", nil),
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.StatusCode != 400 {
		t.Errorf("Expected status code 400, got %d", result.StatusCode)
	}

	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatal("Expected Data to be map[string]interface{}")
	}

	if data["blocked"] != true {
		t.Error("Expected blocked to be true")
	}
}

// TestIDOR_Handle_EmptyInput tests handling empty input
func TestIDOR_Handle_EmptyInput(t *testing.T) {
	m := &IDOR{}

	mockSink := &MockSQLiteSinkIDOR{}

	ctx := &HandlerContext{
		Input:     "",
		Placement: "query_param",
		Param:     "id",
		Config: map[string]interface{}{
			"variant":        "numeric",
			"query_template": "SELECT * FROM users WHERE id = {input}",
			"show_errors":    true,
		},
		Sinks: &SinkContext{
			SQLite: mockSink,
		},
		Request: httptest.NewRequest("GET", "/user?id=", nil),
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.StatusCode != 400 {
		t.Errorf("Expected status code 400, got %d", result.StatusCode)
	}
}

// TestIDOR_Handle_ResourceNotFound tests handling when resource is not found
func TestIDOR_Handle_ResourceNotFound(t *testing.T) {
	m := &IDOR{}

	mockSink := &MockSQLiteSinkIDOR{
		QueryFunc: func(query string) ([]map[string]interface{}, error) {
			return []map[string]interface{}{}, nil // Empty result
		},
	}

	ctx := &HandlerContext{
		Input:     "99999",
		Placement: "query_param",
		Param:     "id",
		Config: map[string]interface{}{
			"variant":        "numeric",
			"query_template": "SELECT * FROM users WHERE id = {input}",
		},
		Sinks: &SinkContext{
			SQLite: mockSink,
		},
		Request: httptest.NewRequest("GET", "/user?id=99999", nil),
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.StatusCode != 404 {
		t.Errorf("Expected status code 404, got %d", result.StatusCode)
	}
}

// TestIDOR_Handle_WeakHeaderAccessControl tests weak header-based access control
func TestIDOR_Handle_WeakHeaderAccessControl(t *testing.T) {
	m := &IDOR{}

	mockSink := &MockSQLiteSinkIDOR{
		QueryFunc: func(query string) ([]map[string]interface{}, error) {
			return []map[string]interface{}{
				{"id": 1, "data": "sensitive"},
			}, nil
		},
	}

	// Test without required header
	req := httptest.NewRequest("GET", "/user?id=1", nil)
	ctx := &HandlerContext{
		Input:     "1",
		Placement: "query_param",
		Param:     "id",
		Config: map[string]interface{}{
			"variant":        "numeric",
			"query_template": "SELECT * FROM users WHERE id = {input}",
			"access_control": "weak_header",
			"show_errors":    true,
		},
		Sinks: &SinkContext{
			SQLite: mockSink,
		},
		Request: req,
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.StatusCode != 403 {
		t.Errorf("Expected status code 403 without header, got %d", result.StatusCode)
	}

	// Test with required header (but still vulnerable to IDOR)
	req2 := httptest.NewRequest("GET", "/user?id=1", nil)
	req2.Header.Set("X-User-ID", "2") // Different user accessing user 1's data
	ctx.Request = req2

	result, err = m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should succeed (vulnerable - no ownership check)
	if result.StatusCode == 403 {
		t.Error("Expected to bypass access control with header")
	}
}

// TestIDOR_Handle_WeakCookieAccessControl tests weak cookie-based access control
func TestIDOR_Handle_WeakCookieAccessControl(t *testing.T) {
	m := &IDOR{}

	mockSink := &MockSQLiteSinkIDOR{
		QueryFunc: func(query string) ([]map[string]interface{}, error) {
			return []map[string]interface{}{
				{"id": 1, "data": "sensitive"},
			}, nil
		},
	}

	// Test without required cookie
	req := httptest.NewRequest("GET", "/user?id=1", nil)
	ctx := &HandlerContext{
		Input:     "1",
		Placement: "query_param",
		Param:     "id",
		Config: map[string]interface{}{
			"variant":        "numeric",
			"query_template": "SELECT * FROM users WHERE id = {input}",
			"access_control": "weak_cookie",
			"show_errors":    true,
		},
		Sinks: &SinkContext{
			SQLite: mockSink,
		},
		Request: req,
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.StatusCode != 403 {
		t.Errorf("Expected status code 403 without cookie, got %d", result.StatusCode)
	}

	// Test with required cookie
	req2 := httptest.NewRequest("GET", "/user?id=1", nil)
	req2.AddCookie(&http.Cookie{Name: "user_id", Value: "2"})
	ctx.Request = req2

	result, err = m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should succeed (vulnerable)
	if result.StatusCode == 403 {
		t.Error("Expected to bypass access control with cookie")
	}
}

// TestIDOR_Handle_RoleBasedAccessControl tests role-based access control bypass
func TestIDOR_Handle_RoleBasedAccessControl(t *testing.T) {
	m := &IDOR{}

	mockSink := &MockSQLiteSinkIDOR{
		QueryFunc: func(query string) ([]map[string]interface{}, error) {
			return []map[string]interface{}{
				{"id": 1, "data": "admin_only_data"},
			}, nil
		},
	}

	// Test as admin - should work
	req := httptest.NewRequest("GET", "/admin/user?id=1", nil)
	req.Header.Set("X-User-Role", "admin")

	ctx := &HandlerContext{
		Input:     "1",
		Placement: "query_param",
		Param:     "id",
		Config: map[string]interface{}{
			"variant":        "numeric",
			"query_template": "SELECT * FROM users WHERE id = {input}",
			"access_control": "role_based",
		},
		Sinks: &SinkContext{
			SQLite: mockSink,
		},
		Request: req,
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.StatusCode == 403 {
		t.Error("Admin should have access")
	}

	// Test as regular user - should also work (IDOR vulnerability)
	req2 := httptest.NewRequest("GET", "/admin/user?id=1", nil)
	req2.Header.Set("X-User-Role", "user")
	ctx.Request = req2

	result, err = m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Vulnerable - regular user can still access
	if result.StatusCode == 403 {
		t.Error("Expected IDOR vulnerability - regular user should access admin data")
	}
}

// TestIDOR_Handle_PredictableTokenAccessControl tests predictable token bypass
func TestIDOR_Handle_PredictableTokenAccessControl(t *testing.T) {
	m := &IDOR{}

	mockSink := &MockSQLiteSinkIDOR{
		QueryFunc: func(query string) ([]map[string]interface{}, error) {
			return []map[string]interface{}{
				{"id": 1, "data": "user_data"},
			}, nil
		},
	}

	// Test without token
	req := httptest.NewRequest("GET", "/user?id=1", nil)
	ctx := &HandlerContext{
		Input:     "1",
		Placement: "query_param",
		Param:     "id",
		Config: map[string]interface{}{
			"variant":        "numeric",
			"query_template": "SELECT * FROM users WHERE id = {input}",
			"access_control": "predictable_token",
			"show_errors":    true,
		},
		Sinks: &SinkContext{
			SQLite: mockSink,
		},
		Request: req,
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.StatusCode != 403 {
		t.Errorf("Expected status code 403 without token, got %d", result.StatusCode)
	}

	// Test with predictable token (user_2 accessing user_1's data)
	req2 := httptest.NewRequest("GET", "/user?id=1", nil)
	req2.Header.Set("Authorization", "Bearer user_2")
	ctx.Request = req2

	result, err = m.Handle(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should succeed - token is valid but doesn't enforce ownership
	if result.StatusCode == 403 {
		t.Error("Expected to bypass access control with predictable token")
	}
}

// TestIDOR_validateInput tests input validation for different variants
func TestIDOR_validateInput(t *testing.T) {
	m := &IDOR{}

	tests := []struct {
		name      string
		input     string
		variant   string
		wantError bool
	}{
		{"valid numeric", "123", "numeric", false},
		{"invalid numeric", "abc", "numeric", true},
		{"empty numeric", "", "numeric", true},
		{"valid uuid", "550e8400-e29b-41d4-a716-446655440000", "uuid", false},
		{"short uuid", "12345", "uuid", true},
		{"valid encoded", "MTIz", "encoded", false},
		{"empty encoded", "", "encoded", true},
		{"valid predictable", "INV-2024-0001", "predictable", false},
		{"empty predictable", "", "predictable", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.validateInput(tt.input, tt.variant)
			if (err != nil) != tt.wantError {
				t.Errorf("validateInput(%q, %q) error = %v, wantError = %v",
					tt.input, tt.variant, err, tt.wantError)
			}
		})
	}
}

// TestIDOR_Registration tests that IDOR module is registered
func TestIDOR_Registration(t *testing.T) {
	module, err := Get("idor")
	if err != nil {
		t.Fatalf("IDOR module not registered: %v", err)
	}

	if module == nil {
		t.Fatal("Expected module, got nil")
	}

	info := module.Info()
	if info.Name != "idor" {
		t.Errorf("Expected module name 'idor', got '%s'", info.Name)
	}
}
