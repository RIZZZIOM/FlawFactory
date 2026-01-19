package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNewExtractor tests extractor creation
func TestNewExtractor(t *testing.T) {
	extractor := NewExtractor()
	if extractor == nil {
		t.Fatal("Expected extractor to be created, got nil")
	}
}

// TestExtract_QueryParam tests query parameter extraction
func TestExtract_QueryParam(t *testing.T) {
	extractor := NewExtractor()

	tests := []struct {
		name     string
		url      string
		param    string
		expected string
	}{
		{"simple value", "/?id=123", "id", "123"},
		{"string value", "/?name=john", "name", "john"},
		{"empty value", "/?empty=", "empty", ""},
		{"missing param", "/?other=value", "missing", ""},
		{"multiple params", "/?a=1&b=2&c=3", "b", "2"},
		{"encoded value", "/?q=hello%20world", "q", "hello world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.url, nil)
			result, err := extractor.Extract(req, "query_param", tt.param)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestExtract_Header tests header extraction
func TestExtract_Header(t *testing.T) {
	extractor := NewExtractor()

	tests := []struct {
		name       string
		headerName string
		headerVal  string
		param      string
		expected   string
	}{
		{"standard header", "X-Custom-Header", "custom-value", "X-Custom-Header", "custom-value"},
		{"content type", "Content-Type", "application/json", "Content-Type", "application/json"},
		{"missing header", "", "", "X-Missing", ""},
		{"authorization", "Authorization", "Bearer token123", "Authorization", "Bearer token123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.headerName != "" {
				req.Header.Set(tt.headerName, tt.headerVal)
			}
			result, err := extractor.Extract(req, "header", tt.param)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestExtract_Cookie tests cookie extraction
func TestExtract_Cookie(t *testing.T) {
	extractor := NewExtractor()

	tests := []struct {
		name       string
		cookieName string
		cookieVal  string
		param      string
		expected   string
	}{
		{"session cookie", "session", "abc123", "session", "abc123"},
		{"user id cookie", "user_id", "42", "user_id", "42"},
		{"missing cookie", "", "", "missing", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.cookieName != "" {
				req.AddCookie(&http.Cookie{Name: tt.cookieName, Value: tt.cookieVal})
			}
			result, err := extractor.Extract(req, "cookie", tt.param)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestExtract_FormField tests form field extraction
func TestExtract_FormField(t *testing.T) {
	extractor := NewExtractor()

	tests := []struct {
		name     string
		formData string
		param    string
		expected string
	}{
		{"simple field", "username=john", "username", "john"},
		{"multiple fields", "a=1&b=2&c=3", "b", "2"},
		{"empty field", "empty=", "empty", ""},
		{"missing field", "other=value", "missing", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/", strings.NewReader(tt.formData))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			result, err := extractor.Extract(req, "form_field", tt.param)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestExtract_JSONField tests JSON field extraction
func TestExtract_JSONField(t *testing.T) {
	extractor := NewExtractor()

	tests := []struct {
		name     string
		json     string
		param    string
		expected string
	}{
		{"simple string", `{"name":"john"}`, "name", "john"},
		{"number", `{"id":123}`, "id", "123"},
		{"boolean true", `{"active":true}`, "active", "true"},
		{"boolean false", `{"active":false}`, "active", "false"},
		{"nested field", `{"user":{"name":"john"}}`, "user.name", "john"},
		{"deep nesting", `{"a":{"b":{"c":"deep"}}}`, "a.b.c", "deep"},
		{"missing field", `{"other":"value"}`, "missing", ""},
		{"null value", `{"value":null}`, "value", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/", strings.NewReader(tt.json))
			req.Header.Set("Content-Type", "application/json")
			result, err := extractor.Extract(req, "json_field", tt.param)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestExtract_JSONField_Invalid tests JSON parsing errors
func TestExtract_JSONField_Invalid(t *testing.T) {
	extractor := NewExtractor()

	req := httptest.NewRequest("POST", "/", strings.NewReader("not valid json"))
	req.Header.Set("Content-Type", "application/json")

	_, err := extractor.Extract(req, "json_field", "field")
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

// TestExtract_UnsupportedPlacement tests unsupported placement error
func TestExtract_UnsupportedPlacement(t *testing.T) {
	extractor := NewExtractor()

	req := httptest.NewRequest("GET", "/", nil)
	_, err := extractor.Extract(req, "unsupported_placement", "param")

	if err == nil {
		t.Error("Expected error for unsupported placement, got nil")
	}

	extractErr, ok := err.(*ExtractionError)
	if !ok {
		t.Fatalf("Expected ExtractionError, got %T", err)
	}

	if extractErr.Placement != "unsupported_placement" {
		t.Errorf("Expected placement 'unsupported_placement', got '%s'", extractErr.Placement)
	}
}

// TestExtract_MultipartForm tests multipart form extraction
func TestExtract_MultipartForm(t *testing.T) {
	extractor := NewExtractor()

	// Create multipart form data
	body := &bytes.Buffer{}
	body.WriteString("--boundary\r\n")
	body.WriteString("Content-Disposition: form-data; name=\"field1\"\r\n\r\n")
	body.WriteString("value1\r\n")
	body.WriteString("--boundary\r\n")
	body.WriteString("Content-Disposition: form-data; name=\"field2\"\r\n\r\n")
	body.WriteString("value2\r\n")
	body.WriteString("--boundary--\r\n")

	req := httptest.NewRequest("POST", "/", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")

	result, err := extractor.Extract(req, "multipart-form", "field1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "value1" {
		t.Errorf("Expected 'value1', got '%s'", result)
	}
}

// TestExtract_MultipartForm_NotMultipart tests error when content type is not multipart
func TestExtract_MultipartForm_NotMultipart(t *testing.T) {
	extractor := NewExtractor()

	req := httptest.NewRequest("POST", "/", strings.NewReader("not multipart"))
	req.Header.Set("Content-Type", "application/json")

	_, err := extractor.Extract(req, "multipart-form", "field")
	if err == nil {
		t.Error("Expected error for non-multipart content, got nil")
	}
}

// TestExtractionError tests ExtractionError formatting
func TestExtractionError(t *testing.T) {
	err := &ExtractionError{
		Placement: "query_param",
		Param:     "id",
		Message:   "test error message",
	}

	expected := "extraction error [query_param:id]: test error message"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

// TestNavigateJSON tests the JSON navigation helper
func TestNavigateJSON(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		path     string
		expected string
	}{
		{
			"top level string",
			map[string]interface{}{"key": "value"},
			"key",
			"value",
		},
		{
			"nested object",
			map[string]interface{}{
				"user": map[string]interface{}{
					"name": "john",
				},
			},
			"user.name",
			"john",
		},
		{
			"three levels deep",
			map[string]interface{}{
				"a": map[string]interface{}{
					"b": map[string]interface{}{
						"c": "deep",
					},
				},
			},
			"a.b.c",
			"deep",
		},
		{
			"missing key",
			map[string]interface{}{"key": "value"},
			"missing",
			"",
		},
		{
			"partial path exists",
			map[string]interface{}{
				"user": map[string]interface{}{
					"name": "john",
				},
			},
			"user.email",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := navigateJSON(tt.data, tt.path)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}
