package modules

import (
	"encoding/json"
	"testing"
)

// TestNoSQLInjectionModuleInfo tests module metadata
func TestNoSQLInjectionModuleInfo(t *testing.T) {
	m := &NoSQLInjection{}
	info := m.Info()

	if info.Name != "nosql_injection" {
		t.Errorf("Expected name 'nosql_injection', got '%s'", info.Name)
	}

	if info.RequiresSink != "" {
		t.Errorf("Expected empty RequiresSink, got '%s'", info.RequiresSink)
	}

	// Check supported placements
	expectedPlacements := []string{"query_param", "path_param", "form_field", "json_field", "header", "cookie"}
	if len(info.SupportedPlacements) != len(expectedPlacements) {
		t.Errorf("Expected %d placements, got %d", len(expectedPlacements), len(info.SupportedPlacements))
	}

	placementMap := make(map[string]bool)
	for _, p := range info.SupportedPlacements {
		placementMap[p] = true
	}

	for _, expected := range expectedPlacements {
		if !placementMap[expected] {
			t.Errorf("Expected placement '%s' not found", expected)
		}
	}
}

// TestNoSQLInjectionModuleRegistered tests that module is registered
func TestNoSQLInjectionModuleRegistered(t *testing.T) {
	if !Has("nosql_injection") {
		t.Error("nosql_injection module should be registered")
	}

	module, err := Get("nosql_injection")
	if err != nil {
		t.Errorf("Failed to get module: %v", err)
	}

	if module == nil {
		t.Error("Module should not be nil")
	}
}

// =============================================================================
// MongoDB Detection Tests
// =============================================================================

func TestDetectMongoDBInjection_Operators(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedType    string
		expectedExploit bool
	}{
		{
			name:            "$ne operator",
			input:           `{"password": {"$ne": ""}}`,
			expectedType:    "operator_ne",
			expectedExploit: true,
		},
		{
			name:            "$gt operator",
			input:           `{"$gt": ""}`,
			expectedType:    "operator_gt",
			expectedExploit: true,
		},
		{
			name:            "$regex operator",
			input:           `{"username": {"$regex": ".*"}}`,
			expectedType:    "operator_regex",
			expectedExploit: true,
		},
		{
			name:            "$where JavaScript",
			input:           `{"$where": "this.password == this.username"}`,
			expectedType:    "javascript_injection",
			expectedExploit: true,
		},
		{
			name:            "$or operator",
			input:           `{"$or": [{"a": 1}, {"b": 2}]}`,
			expectedType:    "operator_or",
			expectedExploit: true,
		},
		{
			name:            "$exists operator",
			input:           `{"admin": {"$exists": true}}`,
			expectedType:    "operator_exists",
			expectedExploit: true,
		},
		{
			name:            "Clean input",
			input:           "john",
			expectedType:    "none",
			expectedExploit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injType, exploitable := detectMongoDBInjection(tt.input, tt.input)
			if injType != tt.expectedType {
				t.Errorf("Expected type '%s', got '%s'", tt.expectedType, injType)
			}
			if exploitable != tt.expectedExploit {
				t.Errorf("Expected exploitable=%v, got %v", tt.expectedExploit, exploitable)
			}
		})
	}
}

func TestDetectMongoDBInjection_JavaScript(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectExploit bool
	}{
		{
			name:          "this reference",
			input:         "this.password",
			expectExploit: true,
		},
		{
			name:          "function keyword",
			input:         "function() { return true; }",
			expectExploit: true,
		},
		{
			name:          "sleep function",
			input:         "sleep(5000)",
			expectExploit: true,
		},
		{
			name:          "db reference",
			input:         "db.users.find()",
			expectExploit: true,
		},
		{
			name:          "require call",
			input:         "require('child_process')",
			expectExploit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, exploitable := detectMongoDBInjection(tt.input, tt.input)
			if exploitable != tt.expectExploit {
				t.Errorf("Expected exploitable=%v, got %v", tt.expectExploit, exploitable)
			}
		})
	}
}

func TestDetectMongoDBInjection_AuthBypass(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Password bypass with $ne",
			input: `{"username": "admin", "password": {"$ne": ""}}`,
		},
		{
			name:  "Password bypass with $gt",
			input: `{"username": "admin", "password": {"$gt": ""}}`,
		},
		{
			name:  "Field exists check",
			input: `{"admin": {"$exists": true}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, exploitable := detectMongoDBInjection(tt.input, tt.input)
			if !exploitable {
				t.Error("Expected auth bypass to be detected as exploitable")
			}
		})
	}
}

// =============================================================================
// Redis Detection Tests
// =============================================================================

func TestDetectRedisInjection(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedType    string
		expectedExploit bool
	}{
		{
			name:            "EVAL command",
			input:           "EVAL 'return 1' 0",
			expectedType:    "lua_injection",
			expectedExploit: true,
		},
		{
			name:            "CONFIG command",
			input:           "CONFIG SET dir /tmp",
			expectedType:    "config_manipulation",
			expectedExploit: true,
		},
		{
			name:            "FLUSHALL command",
			input:           "FLUSHALL",
			expectedType:    "data_destruction",
			expectedExploit: true,
		},
		{
			name:            "KEYS enumeration",
			input:           "KEYS *",
			expectedType:    "key_enumeration",
			expectedExploit: true,
		},
		{
			name:            "CRLF injection",
			input:           "GET user\r\nCONFIG SET dir /tmp",
			expectedType:    "crlf_injection",
			expectedExploit: true,
		},
		{
			name:            "Lua redis.call",
			input:           "redis.call('GET', 'key')",
			expectedType:    "lua_injection",
			expectedExploit: true,
		},
		{
			name:            "SHUTDOWN command",
			input:           "SHUTDOWN",
			expectedType:    "server_shutdown",
			expectedExploit: true,
		},
		{
			name:            "Clean GET command",
			input:           "GET user:123",
			expectedType:    "none",
			expectedExploit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injType, exploitable := detectRedisInjection(tt.input, tt.input)
			if injType != tt.expectedType {
				t.Errorf("Expected type '%s', got '%s'", tt.expectedType, injType)
			}
			if exploitable != tt.expectedExploit {
				t.Errorf("Expected exploitable=%v, got %v", tt.expectedExploit, exploitable)
			}
		})
	}
}

// =============================================================================
// MongoDB Query Processing Tests
// =============================================================================

func TestProcessMongoDBQuery_Find(t *testing.T) {
	result := processMongoDBQuery(
		`{"username": {"$ne": ""}}`,
		"users",
		"find",
		"",
		true,
	)

	if result.Database != "mongodb" {
		t.Errorf("Expected database 'mongodb', got '%s'", result.Database)
	}

	if result.Operation != "find" {
		t.Errorf("Expected operation 'find', got '%s'", result.Operation)
	}

	if !result.Exploitable {
		t.Error("Expected exploitable=true for $ne injection")
	}

	if result.Count == 0 {
		t.Error("Expected results for exploited query")
	}
}

func TestProcessMongoDBQuery_WithTemplate(t *testing.T) {
	result := processMongoDBQuery(
		"admin",
		"users",
		"findOne",
		`{"username": "{input}"}`,
		true,
	)

	if result.Database != "mongodb" {
		t.Errorf("Expected database 'mongodb', got '%s'", result.Database)
	}

	// Clean input should not be exploitable
	if result.Exploitable {
		t.Error("Expected exploitable=false for clean input")
	}
}

func TestProcessMongoDBQuery_AllOperations(t *testing.T) {
	operations := []string{"find", "findOne", "aggregate", "update", "delete", "insert"}

	for _, op := range operations {
		t.Run(op, func(t *testing.T) {
			result := processMongoDBQuery(
				`{"$ne": null}`,
				"users",
				op,
				"",
				true,
			)

			if result.Operation != op {
				t.Errorf("Expected operation '%s', got '%s'", op, result.Operation)
			}
		})
	}
}

// =============================================================================
// Redis Command Processing Tests
// =============================================================================

func TestProcessRedisCommand_Normal(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		operation string
	}{
		{"GET", "GET user:1", "get"},
		{"SET", "SET key value", "set"},
		{"HGETALL", "HGETALL user:1", "hgetall"},
		{"LPUSH", "LPUSH list item", "lpush"},
		{"PING", "PING", "ping"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processRedisCommand(tt.command, tt.operation, "", true)

			if result.Database != "redis" {
				t.Errorf("Expected database 'redis', got '%s'", result.Database)
			}

			if result.Count == 0 {
				t.Error("Expected results from command")
			}
		})
	}
}

func TestProcessRedisCommand_Exploited(t *testing.T) {
	result := processRedisCommand(
		"KEYS *",
		"keys",
		"",
		true,
	)

	if !result.Exploitable {
		t.Error("Expected exploitable=true for KEYS *")
	}

	if result.Warning == "" {
		t.Error("Expected warning for exploited command")
	}
}

// =============================================================================
// Sample Data Tests
// =============================================================================

func TestGetMongoSampleData(t *testing.T) {
	collections := []string{"users", "products", "sessions", "orders", "unknown"}

	for _, col := range collections {
		t.Run(col, func(t *testing.T) {
			data := getMongoSampleData(col)
			if len(data) == 0 {
				t.Errorf("Expected sample data for collection '%s'", col)
			}
		})
	}
}

func TestGetRedisSampleValue(t *testing.T) {
	keys := []string{"user:1", "user:admin", "session:abc123", "unknown_key"}

	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			value := getRedisSampleValue(key)
			if value == nil {
				t.Errorf("Expected value for key '%s'", key)
			}
		})
	}
}

// =============================================================================
// Handle Tests
// =============================================================================

func TestNoSQLInjectionHandle_MongoDB(t *testing.T) {
	m := &NoSQLInjection{}

	ctx := &HandlerContext{
		Input: `{"username": {"$ne": ""}}`,
		Config: map[string]interface{}{
			"database":   "mongodb",
			"collection": "users",
			"operation":  "find",
		},
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

func TestNoSQLInjectionHandle_Redis(t *testing.T) {
	m := &NoSQLInjection{}

	ctx := &HandlerContext{
		Input: "GET user:1",
		Config: map[string]interface{}{
			"database":  "redis",
			"operation": "get",
		},
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

func TestNoSQLInjectionHandle_QueryTemplate(t *testing.T) {
	m := &NoSQLInjection{}

	ctx := &HandlerContext{
		Input: "admin",
		Config: map[string]interface{}{
			"database":       "mongodb",
			"collection":     "users",
			"operation":      "findOne",
			"query_template": `{"username": "{input}"}`,
		},
	}

	result, err := m.Handle(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

// =============================================================================
// NoSQLResult Struct Tests
// =============================================================================

func TestNoSQLResult_JSON(t *testing.T) {
	result := &NoSQLResult{
		Database:      "mongodb",
		Operation:     "find",
		InjectionType: "operator_ne",
		Exploitable:   true,
		Results: []map[string]interface{}{
			{"_id": "1", "username": "admin"},
		},
		Count:   1,
		Warning: "MongoDB operator_ne injection detected",
	}

	// Test JSON marshaling
	data, err := json.Marshal(result)
	if err != nil {
		t.Errorf("Failed to marshal result: %v", err)
	}

	// Verify it contains expected fields
	if !contains(string(data), "mongodb") {
		t.Error("JSON should contain database field")
	}
	if !contains(string(data), "operator_ne") {
		t.Error("JSON should contain injection_type field")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestProcessMongoDBQuery_EmptyInput(t *testing.T) {
	result := processMongoDBQuery("", "users", "find", "", true)
	if result == nil {
		t.Error("Result should not be nil for empty input")
	}
}

func TestProcessRedisCommand_EmptyInput(t *testing.T) {
	result := processRedisCommand("", "get", "", true)
	if result == nil {
		t.Error("Result should not be nil for empty input")
	}
}

func TestProcessMongoDBQuery_InvalidJSON(t *testing.T) {
	result := processMongoDBQuery("not valid json {{{", "users", "find", "", true)
	if result == nil {
		t.Error("Result should not be nil for invalid JSON")
	}
	// Should still process as field value
	if result.Query == nil {
		t.Error("Query should be set even for invalid JSON")
	}
}

func TestEmulateMongoFind_AllInjectionTypes(t *testing.T) {
	injectionTypes := []string{
		"operator_ne",
		"auth_bypass",
		"operator_gt",
		"operator_exists",
		"javascript_injection",
		"operator_regex",
		"none",
	}

	for _, injType := range injectionTypes {
		t.Run(injType, func(t *testing.T) {
			exploitable := injType != "none"
			results, count := emulateMongoFind("users", nil, injType, exploitable)
			if exploitable && count == 0 {
				t.Errorf("Expected results for exploitable injection type '%s'", injType)
			}
			_ = results // Use results to avoid unused variable warning
		})
	}
}

func TestEmulateRedisCommand_AllCommands(t *testing.T) {
	commands := []string{
		"GET key",
		"SET key value",
		"HGET hash field",
		"HGETALL hash",
		"LPUSH list item",
		"RPUSH list item",
		"LRANGE list 0 -1",
		"SMEMBERS set",
		"ZADD zset 1 member",
		"ZRANGE zset 0 -1",
		"EXISTS key",
		"DEL key",
		"INCR counter",
		"DECR counter",
		"TTL key",
		"PING",
		"INFO",
		"UNKNOWN command",
	}

	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			results, _ := emulateRedisCommand(cmd, "none", false)
			if results == nil {
				t.Errorf("Expected results for command '%s'", cmd)
			}
		})
	}
}

func TestSimulateMongoDBDelay(t *testing.T) {
	tests := []struct {
		query       string
		expectDelay bool
	}{
		{"sleep(1000)", true},
		{"sleep(5000)", true},
		{"normal query", false},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			delay := SimulateMongoDBDelay(tt.query)
			hasDelay := delay > 0
			if hasDelay != tt.expectDelay {
				t.Errorf("Expected delay=%v, got %v", tt.expectDelay, hasDelay)
			}
		})
	}
}
