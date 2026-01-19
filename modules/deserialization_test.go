package modules

import (
	"encoding/base64"
	"testing"
)

// TestDeserializationModuleInfo tests module metadata
func TestDeserializationModuleInfo(t *testing.T) {
	m := &Deserialization{}
	info := m.Info()

	if info.Name != "insecure_deserialization" {
		t.Errorf("Expected name 'insecure_deserialization', got '%s'", info.Name)
	}

	if info.RequiresSink != "" {
		t.Errorf("Expected empty RequiresSink, got '%s'", info.RequiresSink)
	}

	// Check supported placements
	expectedPlacements := []string{"query_param", "form_field", "json_field", "header", "cookie"}
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

// TestDeserializationModuleRegistered tests that module is registered
func TestDeserializationModuleRegistered(t *testing.T) {
	if !Has("insecure_deserialization") {
		t.Error("insecure_deserialization module should be registered")
	}

	module, err := Get("insecure_deserialization")
	if err != nil {
		t.Errorf("Failed to get module: %v", err)
	}

	if module == nil {
		t.Error("Module should not be nil")
	}
}

// TestDetectSerializationFormat tests format detection
func TestDetectSerializationFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Java magic bytes",
			input:    "\xac\xed\x00\x05",
			expected: "java",
		},
		{
			name:     "Java base64 prefix",
			input:    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA",
			expected: "java",
		},
		{
			name:     "Java commons collections pattern",
			input:    "org.apache.commons.collections.functors.InvokerTransformer",
			expected: "java",
		},
		{
			name:     "PHP serialized object",
			input:    `O:8:"stdClass":1:{s:4:"test";s:5:"value";}`,
			expected: "php",
		},
		{
			name:     "PHP serialized array",
			input:    `a:2:{s:4:"key1";s:6:"value1";s:4:"key2";i:123;}`,
			expected: "php",
		},
		{
			name:     "Python pickle protocol 0",
			input:    "cos\nsystem\n(S'whoami'\ntR.",
			expected: "python_pickle",
		},
		{
			name:     "Python pickle posix",
			input:    "cposix\nsystem\n(S'id'\ntR.",
			expected: "python_pickle",
		},
		{
			name:     "DotNet pattern",
			input:    "System.Windows.Data.ObjectDataProvider",
			expected: "dotnet",
		},
		{
			name:     "Unknown format",
			input:    "just plain text",
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectSerializationFormat(tt.input)
			if result != tt.expected {
				t.Errorf("Expected format '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestProcessJavaSerialized tests Java deserialization processing
func TestProcessJavaSerialized(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectExploit bool
		expectGadget  string
		expectWarning bool
	}{
		{
			name:          "Commons Collections gadget",
			input:         "org.apache.commons.collections.functors.InvokerTransformer",
			expectExploit: true,
			expectGadget:  "CommonsCollections",
			expectWarning: true,
		},
		{
			name:          "Spring gadget",
			input:         "org.springframework.beans.factory.ObjectFactory",
			expectExploit: true,
			expectGadget:  "Spring",
			expectWarning: true,
		},
		{
			name:          "Runtime exec pattern",
			input:         "java.lang.Runtime.getRuntime().exec(\"whoami\")",
			expectExploit: true,
			expectGadget:  "Runtime.exec",
			expectWarning: true,
		},
		{
			name:          "Hibernate gadget",
			input:         "org.hibernate.tuple.component",
			expectExploit: true,
			expectGadget:  "Hibernate",
			expectWarning: true,
		},
		{
			name:          "Safe Java data",
			input:         "\xac\xed\x00\x05sr\x00\x10SafeClassName",
			expectExploit: false,
			expectGadget:  "",
			expectWarning: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &DeserializationResult{}
			processJavaSerialized(result, tt.input, true)

			if result.Exploitable != tt.expectExploit {
				t.Errorf("Expected Exploitable=%v, got %v", tt.expectExploit, result.Exploitable)
			}

			if tt.expectGadget != "" && result.GadgetChain != tt.expectGadget {
				t.Errorf("Expected GadgetChain='%s', got '%s'", tt.expectGadget, result.GadgetChain)
			}

			if tt.expectWarning && result.Warning == "" {
				t.Error("Expected warning message but got none")
			}
		})
	}
}

// TestProcessPHPSerialized tests PHP deserialization processing
func TestProcessPHPSerialized(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectExploit bool
		expectClass   string
		expectWarning bool
	}{
		{
			name:          "PHP object with __wakeup",
			input:         `O:10:"TestClass":1:{s:8:"__wakeup";s:4:"test";}`,
			expectExploit: true,
			expectClass:   "TestClass",
			expectWarning: true,
		},
		{
			name:          "PHP object with system call",
			input:         `O:12:"EvilClass":1:{s:3:"cmd";s:17:"system('whoami')";}`,
			expectExploit: true,
			expectClass:   "EvilClass",
			expectWarning: true,
		},
		{
			name:          "Guzzle gadget chain",
			input:         `O:24:"GuzzleHttp\\Psr7\\Request":1:{s:4:"body";s:4:"test";}`,
			expectExploit: true,
			expectClass:   "",
			expectWarning: true,
		},
		{
			name:          "Safe PHP object",
			input:         `O:8:"stdClass":1:{s:4:"name";s:5:"value";}`,
			expectExploit: false,
			expectClass:   "stdClass",
			expectWarning: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &DeserializationResult{}
			processPHPSerialized(result, tt.input, true)

			if result.Exploitable != tt.expectExploit {
				t.Errorf("Expected Exploitable=%v, got %v", tt.expectExploit, result.Exploitable)
			}

			if tt.expectClass != "" && result.ClassName != tt.expectClass {
				t.Errorf("Expected ClassName='%s', got '%s'", tt.expectClass, result.ClassName)
			}

			if tt.expectWarning && result.Warning == "" {
				t.Error("Expected warning message but got none")
			}
		})
	}
}

// TestProcessPythonPickle tests Python pickle processing
func TestProcessPythonPickle(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectExploit bool
	}{
		{
			name:          "os.system call",
			input:         "cos\nsystem\n(S'whoami'\ntR.",
			expectExploit: true,
		},
		{
			name:          "subprocess pattern",
			input:         "subprocess.call(['id'])",
			expectExploit: true,
		},
		{
			name:          "__reduce__ pattern",
			input:         "__reduce__",
			expectExploit: true,
		},
		{
			name:          "Safe pickle",
			input:         "\x80\x04\x95\x08\x00\x00\x00\x00\x00\x00\x00}",
			expectExploit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &DeserializationResult{}
			processPythonPickle(result, tt.input, true)

			if result.Exploitable != tt.expectExploit {
				t.Errorf("Expected Exploitable=%v, got %v", tt.expectExploit, result.Exploitable)
			}
		})
	}
}

// TestProcessDotNetSerialized tests .NET deserialization processing
func TestProcessDotNetSerialized(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectExploit bool
		expectGadget  string
	}{
		{
			name:          "ObjectDataProvider gadget",
			input:         "System.Windows.Data.ObjectDataProvider",
			expectExploit: true,
			expectGadget:  "ObjectDataProvider",
		},
		{
			name:          "Process.Start pattern",
			input:         "System.Diagnostics.Process.Start",
			expectExploit: true,
			expectGadget:  "Process.Start",
		},
		{
			name:          "Safe .NET data",
			input:         "\x00\x01\x00\x00\x00\xff\xff\xff\xff",
			expectExploit: false,
			expectGadget:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &DeserializationResult{}
			processDotNetSerialized(result, tt.input, true)

			if result.Exploitable != tt.expectExploit {
				t.Errorf("Expected Exploitable=%v, got %v", tt.expectExploit, result.Exploitable)
			}

			if tt.expectGadget != "" && result.GadgetChain != tt.expectGadget {
				t.Errorf("Expected GadgetChain='%s', got '%s'", tt.expectGadget, result.GadgetChain)
			}
		})
	}
}

// TestParsePHPSerialized tests PHP serialized data parsing
func TestParsePHPSerialized(t *testing.T) {
	input := `O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}`

	props := parsePHPSerialized(input)

	if props["name"] != "admin" {
		t.Errorf("Expected name='admin', got '%v'", props["name"])
	}

	if props["role"] != "admin" {
		t.Errorf("Expected role='admin', got '%v'", props["role"])
	}
}

// TestIsBase64 tests base64 detection
func TestIsBase64(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"SGVsbG8gV29ybGQ=", true},
		{"rO0ABXNyAA==", true},
		{"plain text with spaces", false},
		{"abc", false},      // too short
		{"SGVsbG8!", false}, // invalid character
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isBase64(tt.input)
			if result != tt.expected {
				t.Errorf("Expected isBase64('%s')=%v, got %v", tt.input, tt.expected, result)
			}
		})
	}
}

// TestExtractCommand tests command extraction
func TestExtractCommand(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "PHP system call",
			input:    `system('whoami')`,
			expected: "whoami",
		},
		{
			name:     "PHP exec call",
			input:    `exec("id")`,
			expected: "id",
		},
		{
			name:     "Java Runtime exec",
			input:    `Runtime.getRuntime().exec("calc.exe")`,
			expected: "calc.exe",
		},
		{
			name:     "Direct command",
			input:    "calc.exe",
			expected: "calc.exe",
		},
		{
			name:     "No command",
			input:    "just regular data",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCommand(tt.input)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestDeserializationFilter tests input filtering
func TestDeserializationFilter(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		filter      string
		config      map[string]interface{}
		expectBlock bool
	}{
		{
			name:        "No filter",
			input:       "anything goes",
			filter:      "none",
			config:      nil,
			expectBlock: false,
		},
		{
			name:        "Basic signature - Java magic bytes",
			input:       "rO0ABXNyAA==",
			filter:      "basic_signature",
			config:      nil,
			expectBlock: true,
		},
		{
			name:        "Basic signature - Clean data",
			input:       "clean data",
			filter:      "basic_signature",
			config:      nil,
			expectBlock: false,
		},
		{
			name:        "Basic class - Commons Collections",
			input:       "org.apache.commons.collections.Transformer",
			filter:      "basic_class",
			config:      nil,
			expectBlock: true,
		},
		{
			name:        "Basic class - Safe class",
			input:       "com.myapp.SafeClass",
			filter:      "basic_class",
			config:      nil,
			expectBlock: false,
		},
		{
			name:        "PHP basic - Object",
			input:       `O:8:"stdClass":0:{}`,
			filter:      "php_basic",
			config:      nil,
			expectBlock: true,
		},
		{
			name:        "PHP basic - Clean",
			input:       "clean data",
			filter:      "php_basic",
			config:      nil,
			expectBlock: false,
		},
		{
			name:   "Blocklist - Matched",
			input:  "contains evil_pattern here",
			filter: "blocklist",
			config: map[string]interface{}{
				"blocked_patterns": []interface{}{"evil_pattern", "bad_stuff"},
			},
			expectBlock: true,
		},
		{
			name:   "Blocklist - Clean",
			input:  "safe content",
			filter: "blocklist",
			config: map[string]interface{}{
				"blocked_patterns": []interface{}{"evil_pattern"},
			},
			expectBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, _ := applyDeserializationFilter(tt.input, tt.filter, tt.config)
			if blocked != tt.expectBlock {
				t.Errorf("Expected blocked=%v, got %v", tt.expectBlock, blocked)
			}
		})
	}
}

// TestDeserializationHandle tests the main Handle function
func TestDeserializationHandle(t *testing.T) {
	m := &Deserialization{}

	tests := []struct {
		name      string
		input     string
		config    map[string]interface{}
		expectErr bool
	}{
		{
			name:  "Java payload",
			input: "org.apache.commons.collections.functors.InvokerTransformer",
			config: map[string]interface{}{
				"format":            "auto",
				"filter":            "none",
				"show_decoded":      true,
				"emulate_execution": true,
			},
			expectErr: false,
		},
		{
			name:  "PHP payload",
			input: `O:8:"stdClass":1:{s:4:"test";s:5:"value";}`,
			config: map[string]interface{}{
				"format":            "php",
				"filter":            "none",
				"show_decoded":      true,
				"emulate_execution": true,
			},
			expectErr: false,
		},
		{
			name:  "Base64 encoded Java",
			input: base64.StdEncoding.EncodeToString([]byte("\xac\xed\x00\x05test")),
			config: map[string]interface{}{
				"format":       "auto",
				"filter":       "none",
				"show_decoded": true,
			},
			expectErr: false,
		},
		{
			name:  "Filtered payload",
			input: "org.apache.commons.collections",
			config: map[string]interface{}{
				"format": "auto",
				"filter": "basic_class",
			},
			expectErr: false, // Returns result with blocked=true, not an error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &HandlerContext{
				Input:  tt.input,
				Config: tt.config,
			}

			result, err := m.Handle(ctx)

			if tt.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if result == nil {
				t.Error("Result should not be nil")
			}
		})
	}
}

// TestProcessSerializedDataAutoDetect tests auto-detection in processSerializedData
func TestProcessSerializedDataAutoDetect(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedFormat string
	}{
		{
			name:           "Auto detect Java",
			input:          "org.apache.commons.collections.Transformer",
			expectedFormat: "java",
		},
		{
			name:           "Auto detect PHP",
			input:          `O:4:"Test":0:{}`,
			expectedFormat: "php",
		},
		{
			name:           "Auto detect Python",
			input:          "cos\nsystem\n(S'whoami'\ntR.",
			expectedFormat: "python_pickle",
		},
		{
			name:           "Auto detect .NET",
			input:          "System.Diagnostics.Process",
			expectedFormat: "dotnet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processSerializedData(tt.input, "auto", false, false)
			if result.Format != tt.expectedFormat {
				t.Errorf("Expected format '%s', got '%s'", tt.expectedFormat, result.Format)
			}
		})
	}
}

// TestDeserializationResultFields tests that result fields are properly set
func TestDeserializationResultFields(t *testing.T) {
	result := &DeserializationResult{
		Format:       "java",
		Detected:     true,
		PayloadType:  "gadget_chain",
		ClassName:    "org.test.Class",
		RawPayload:   "raw data",
		Decoded:      "decoded data",
		Warning:      "test warning",
		Exploitable:  true,
		GadgetChain:  "CommonsCollections",
		SimulatedCmd: "whoami",
	}

	if result.Format != "java" {
		t.Errorf("Format mismatch")
	}
	if !result.Detected {
		t.Error("Detected should be true")
	}
	if !result.Exploitable {
		t.Error("Exploitable should be true")
	}
	if result.GadgetChain != "CommonsCollections" {
		t.Error("GadgetChain mismatch")
	}
	if result.SimulatedCmd != "whoami" {
		t.Error("SimulatedCmd mismatch")
	}
}

// TestExtractJavaClassName tests Java class name extraction
func TestExtractJavaClassName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Dot notation class",
			input:    "org.apache.commons.Test",
			expected: "org.apache.commons.Test",
		},
		{
			name:     "No class name",
			input:    "random data",
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractJavaClassName(tt.input)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}
