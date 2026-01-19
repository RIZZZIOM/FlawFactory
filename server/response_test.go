package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNewResponseBuilder tests response builder creation
func TestNewResponseBuilder(t *testing.T) {
	rb := NewResponseBuilder()
	if rb == nil {
		t.Fatal("Expected response builder to be created, got nil")
	}
}

// TestResponseBuilder_SendJSON tests JSON response formatting
func TestResponseBuilder_SendJSON(t *testing.T) {
	rb := NewResponseBuilder()
	w := httptest.NewRecorder()

	data := map[string]interface{}{
		"message": "hello",
		"count":   42,
	}

	rb.Send(w, "json", data)

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Check status code
	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var response ResponseData
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	// Check data is present
	if response.Data == nil {
		t.Error("Expected data in response, got nil")
	}
}

// TestResponseBuilder_SendHTML tests HTML response formatting
func TestResponseBuilder_SendHTML(t *testing.T) {
	rb := NewResponseBuilder()
	w := httptest.NewRecorder()

	rb.Send(w, "html", "<h1>Hello</h1>")

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected Content-Type to contain 'text/html', got '%s'", contentType)
	}

	// Check body contains HTML structure
	body := w.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("Expected HTML doctype in response")
	}
	if !strings.Contains(body, "<h1>Hello</h1>") {
		t.Error("Expected content in HTML body")
	}
}

// TestResponseBuilder_SendText tests plain text response formatting
func TestResponseBuilder_SendText(t *testing.T) {
	rb := NewResponseBuilder()
	w := httptest.NewRecorder()

	rb.Send(w, "text", "Hello, World!")

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("Expected Content-Type to contain 'text/plain', got '%s'", contentType)
	}

	// Check body
	body := w.Body.String()
	if !strings.Contains(body, "Hello, World!") {
		t.Errorf("Expected 'Hello, World!' in body, got '%s'", body)
	}
}

// TestResponseBuilder_SendXML tests XML response formatting
func TestResponseBuilder_SendXML(t *testing.T) {
	rb := NewResponseBuilder()
	w := httptest.NewRecorder()

	rb.Send(w, "xml", "test data")

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/xml") {
		t.Errorf("Expected Content-Type to contain 'application/xml', got '%s'", contentType)
	}

	// Check XML declaration
	body := w.Body.String()
	if !strings.Contains(body, "<?xml") {
		t.Error("Expected XML declaration in response")
	}
}

// TestResponseBuilder_SendError tests error response formatting
func TestResponseBuilder_SendError(t *testing.T) {
	rb := NewResponseBuilder()
	w := httptest.NewRecorder()

	debug := DebugInfo{
		Message:   "Something went wrong",
		Module:    "test_module",
		Placement: "query_param",
		Param:     "id",
	}

	rb.SendError(w, "json", 500, "Internal Server Error", debug)

	// Check status code
	if w.Code != 500 {
		t.Errorf("Expected status 500, got %d", w.Code)
	}

	// Parse response
	var response ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}

	// Check error field
	if response.Error != "Internal Server Error" {
		t.Errorf("Expected error 'Internal Server Error', got '%s'", response.Error)
	}

	// Check debug info
	if response.Debug.Message != "Something went wrong" {
		t.Errorf("Expected debug message 'Something went wrong', got '%s'", response.Debug.Message)
	}
	if response.Debug.Module != "test_module" {
		t.Errorf("Expected module 'test_module', got '%s'", response.Debug.Module)
	}
}

// TestResponseBuilder_SendErrorHTML tests HTML error response
func TestResponseBuilder_SendErrorHTML(t *testing.T) {
	rb := NewResponseBuilder()
	w := httptest.NewRecorder()

	debug := DebugInfo{
		Message: "Error details",
		Module:  "test",
	}

	rb.SendError(w, "html", 400, "Bad Request", debug)

	// Check status code
	if w.Code != 400 {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// Check HTML content
	body := w.Body.String()
	if !strings.Contains(body, "Bad Request") {
		t.Error("Expected error message in HTML body")
	}
	if !strings.Contains(body, "Debug Information") {
		t.Error("Expected debug section in HTML body")
	}
}

// TestResponseBuilder_SendErrorText tests text error response
func TestResponseBuilder_SendErrorText(t *testing.T) {
	rb := NewResponseBuilder()
	w := httptest.NewRecorder()

	debug := DebugInfo{
		Message:   "Detailed error",
		Module:    "mod",
		Placement: "header",
		Param:     "auth",
	}

	rb.SendError(w, "text", 401, "Unauthorized", debug)

	body := w.Body.String()
	if !strings.Contains(body, "ERROR: Unauthorized") {
		t.Error("Expected error message in text body")
	}
	if !strings.Contains(body, "DEBUG INFO:") {
		t.Error("Expected debug info in text body")
	}
}

// TestResponseBuilder_SendRaw tests raw response sending
func TestResponseBuilder_SendRaw(t *testing.T) {
	rb := NewResponseBuilder()

	tests := []struct {
		name         string
		responseType string
		statusCode   int
		data         interface{}
	}{
		{"raw json", "json", 200, map[string]string{"key": "value"}},
		{"raw html", "html", 201, "<p>Created</p>"},
		{"raw text", "text", 204, "No Content"},
		{"raw xml", "xml", 200, "xml data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			rb.SendRaw(w, tt.responseType, tt.statusCode, tt.data)

			if w.Code != tt.statusCode {
				t.Errorf("Expected status %d, got %d", tt.statusCode, w.Code)
			}
		})
	}
}

// TestResponseBuilder_SendCombined tests combined results response
func TestResponseBuilder_SendCombined(t *testing.T) {
	rb := NewResponseBuilder()
	w := httptest.NewRecorder()

	results := []ModuleResult{
		{Module: "module1", Param: "param1", Data: "data1"},
		{Module: "module2", Param: "param2", Data: "data2"},
	}

	rb.SendCombined(w, "json", results)

	// Parse response
	var response struct {
		Data struct {
			Results []ModuleResult `json:"results"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse combined response: %v", err)
	}

	if len(response.Data.Results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(response.Data.Results))
	}
}

// TestResponseBuilder_DefaultToJSON tests default response type is JSON
func TestResponseBuilder_DefaultToJSON(t *testing.T) {
	rb := NewResponseBuilder()
	w := httptest.NewRecorder()

	rb.Send(w, "unknown_type", map[string]string{"test": "data"})

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected default Content-Type 'application/json', got '%s'", contentType)
	}
}

// TestDebugInfo tests DebugInfo struct
func TestDebugInfo(t *testing.T) {
	debug := DebugInfo{
		Message:   "test message",
		Module:    "test_module",
		Placement: "query_param",
		Param:     "id",
	}

	if debug.Message != "test message" {
		t.Errorf("Expected Message 'test message', got '%s'", debug.Message)
	}
	if debug.Module != "test_module" {
		t.Errorf("Expected Module 'test_module', got '%s'", debug.Module)
	}
}

// TestModuleResult tests ModuleResult struct
func TestModuleResult(t *testing.T) {
	result := ModuleResult{
		Module: "sql_injection",
		Param:  "id",
		Data:   []string{"result1", "result2"},
		Error:  "",
	}

	if result.Module != "sql_injection" {
		t.Errorf("Expected Module 'sql_injection', got '%s'", result.Module)
	}
	if result.Param != "id" {
		t.Errorf("Expected Param 'id', got '%s'", result.Param)
	}
	if result.Error != "" {
		t.Errorf("Expected empty Error, got '%s'", result.Error)
	}
}

// TestCombinedResult tests CombinedResult struct
func TestCombinedResult(t *testing.T) {
	combined := CombinedResult{
		Results: []ModuleResult{
			{Module: "mod1", Param: "p1"},
			{Module: "mod2", Param: "p2"},
		},
	}

	if len(combined.Results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(combined.Results))
	}
}
