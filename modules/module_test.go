package modules

import (
	"testing"
)

// TestModuleInfo tests ModuleInfo struct
func TestModuleInfo(t *testing.T) {
	info := ModuleInfo{
		Name:                "test_module",
		Description:         "A test module",
		SupportedPlacements: []string{"query_param", "header"},
		RequiresSink:        "sqlite",
	}

	if info.Name != "test_module" {
		t.Errorf("Expected Name 'test_module', got '%s'", info.Name)
	}
	if info.Description != "A test module" {
		t.Errorf("Expected Description 'A test module', got '%s'", info.Description)
	}
	if len(info.SupportedPlacements) != 2 {
		t.Errorf("Expected 2 placements, got %d", len(info.SupportedPlacements))
	}
	if info.RequiresSink != "sqlite" {
		t.Errorf("Expected RequiresSink 'sqlite', got '%s'", info.RequiresSink)
	}
}

// TestModuleInfo_Placements tests placement listing
func TestModuleInfo_Placements(t *testing.T) {
	info := ModuleInfo{
		Name: "placement_test",
		SupportedPlacements: []string{
			"query_param",
			"path_param",
			"header",
			"cookie",
			"form_field",
			"json_field",
			"multipart-form",
		},
	}

	if len(info.SupportedPlacements) != 7 {
		t.Errorf("Expected 7 placements, got %d", len(info.SupportedPlacements))
	}
}

// TestHandlerContext tests HandlerContext struct
func TestHandlerContext(t *testing.T) {
	ctx := &HandlerContext{
		Input:     "test input",
		Placement: "query_param",
		Param:     "id",
		Config: map[string]interface{}{
			"key1": "value1",
			"key2": 42,
		},
	}

	if ctx.Input != "test input" {
		t.Errorf("Expected Input 'test input', got '%s'", ctx.Input)
	}
	if ctx.Placement != "query_param" {
		t.Errorf("Expected Placement 'query_param', got '%s'", ctx.Placement)
	}
	if ctx.Param != "id" {
		t.Errorf("Expected Param 'id', got '%s'", ctx.Param)
	}
	if ctx.Config["key1"] != "value1" {
		t.Errorf("Expected Config[key1] 'value1', got '%v'", ctx.Config["key1"])
	}
}

// TestHandlerContext_EmptyConfig tests empty config
func TestHandlerContext_EmptyConfig(t *testing.T) {
	ctx := &HandlerContext{
		Input:     "input",
		Placement: "header",
		Param:     "auth",
		Config:    nil,
	}

	if ctx.Config != nil {
		t.Error("Expected nil Config")
	}
}

// TestHandlerContext_GetConfigString tests GetConfigString helper
func TestHandlerContext_GetConfigString(t *testing.T) {
	ctx := &HandlerContext{
		Config: map[string]interface{}{
			"str_key": "string_value",
			"int_key": 42,
		},
	}

	// Test existing string key
	val := ctx.GetConfigString("str_key", "default")
	if val != "string_value" {
		t.Errorf("Expected 'string_value', got '%s'", val)
	}

	// Test missing key
	val = ctx.GetConfigString("missing", "default")
	if val != "default" {
		t.Errorf("Expected 'default', got '%s'", val)
	}

	// Test nil config
	ctx2 := &HandlerContext{Config: nil}
	val = ctx2.GetConfigString("any", "default")
	if val != "default" {
		t.Errorf("Expected 'default' for nil config, got '%s'", val)
	}
}

// TestHandlerContext_GetConfigBool tests GetConfigBool helper
func TestHandlerContext_GetConfigBool(t *testing.T) {
	ctx := &HandlerContext{
		Config: map[string]interface{}{
			"bool_true":  true,
			"bool_false": false,
		},
	}

	// Test existing bool key
	val := ctx.GetConfigBool("bool_true", false)
	if !val {
		t.Error("Expected true, got false")
	}

	// Test missing key
	val = ctx.GetConfigBool("missing", true)
	if !val {
		t.Error("Expected default true, got false")
	}
}

// TestHandlerContext_GetConfigInt tests GetConfigInt helper
func TestHandlerContext_GetConfigInt(t *testing.T) {
	ctx := &HandlerContext{
		Config: map[string]interface{}{
			"int_key":   42,
			"float_key": 3.14,
		},
	}

	// Test existing int key
	val := ctx.GetConfigInt("int_key", 0)
	if val != 42 {
		t.Errorf("Expected 42, got %d", val)
	}

	// Test float (converted to int)
	val = ctx.GetConfigInt("float_key", 0)
	if val != 3 {
		t.Errorf("Expected 3, got %d", val)
	}

	// Test missing key
	val = ctx.GetConfigInt("missing", 100)
	if val != 100 {
		t.Errorf("Expected 100, got %d", val)
	}
}

// TestSinkContext tests SinkContext struct
func TestSinkContext(t *testing.T) {
	sinkCtx := &SinkContext{
		SQLite:     nil,
		Filesystem: nil,
		Command:    nil,
		HTTP:       nil,
	}

	// All sinks should be nil initially
	if sinkCtx.SQLite != nil {
		t.Error("Expected nil SQLite")
	}
	if sinkCtx.Filesystem != nil {
		t.Error("Expected nil Filesystem")
	}
	if sinkCtx.Command != nil {
		t.Error("Expected nil Command")
	}
	if sinkCtx.HTTP != nil {
		t.Error("Expected nil HTTP")
	}
}

// TestResult tests Result struct
func TestResult(t *testing.T) {
	result := &Result{
		Data:       "result data",
		StatusCode: 200,
	}

	if result.Data != "result data" {
		t.Errorf("Expected Data 'result data', got '%v'", result.Data)
	}
	if result.StatusCode != 200 {
		t.Errorf("Expected StatusCode 200, got %d", result.StatusCode)
	}
}

// TestResult_WithError tests Result with error
func TestResult_WithError(t *testing.T) {
	result := &Result{
		Error: "something went wrong",
	}

	if result.Error != "something went wrong" {
		t.Errorf("Expected error 'something went wrong', got '%s'", result.Error)
	}
}

// TestNewResult tests NewResult helper function
func TestNewResult(t *testing.T) {
	result := NewResult("test data")

	if result.Data != "test data" {
		t.Errorf("Expected 'test data', got '%v'", result.Data)
	}
}

// TestNewErrorResult tests NewErrorResult helper function
func TestNewErrorResult(t *testing.T) {
	result := NewErrorResult("error message")

	if result.Error != "error message" {
		t.Errorf("Expected 'error message', got '%s'", result.Error)
	}
}

// TestResult_DataTypes tests Result with different data types
func TestResult_DataTypes(t *testing.T) {
	tests := []struct {
		name string
		data interface{}
	}{
		{"string data", "string value"},
		{"int data", 42},
		{"slice data", []string{"a", "b", "c"}},
		{"map data", map[string]int{"x": 1, "y": 2}},
		{"nil data", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &Result{
				Data: tt.data,
			}

			// Just verify no panic
			_ = result.Data
		})
	}
}

// TestHTTPResponse tests HTTPResponse struct in modules package
func TestHTTPResponse_Module(t *testing.T) {
	resp := HTTPResponse{
		StatusCode: 200,
		Body:       "response body",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected StatusCode 200, got %d", resp.StatusCode)
	}
	if resp.Body != "response body" {
		t.Errorf("Expected body 'response body', got '%s'", resp.Body)
	}
}

// TestHTTPOptions tests HTTPOptions struct in modules package
func TestHTTPOptions_Module(t *testing.T) {
	opts := HTTPOptions{
		Method:          "POST",
		Headers:         map[string]string{"X-Test": "value"},
		Body:            "request body",
		FollowRedirects: true,
		Timeout:         30,
	}

	if opts.Method != "POST" {
		t.Errorf("Expected Method 'POST', got '%s'", opts.Method)
	}
	if !opts.FollowRedirects {
		t.Error("Expected FollowRedirects true")
	}
	if opts.Timeout != 30 {
		t.Errorf("Expected Timeout 30, got %d", opts.Timeout)
	}
}
