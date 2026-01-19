package modules

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// Deserialization implements the insecure_deserialization vulnerability module
type Deserialization struct{}

// init registers the module
func init() {
	Register(&Deserialization{})
}

// Info returns module metadata
func (m *Deserialization) Info() ModuleInfo {
	return ModuleInfo{
		Name:        "insecure_deserialization",
		Description: "Insecure Deserialization vulnerability that emulates processing of Java/PHP serialized objects",
		SupportedPlacements: []string{
			"query_param",
			"form_field",
			"json_field",
			"header",
			"cookie",
		},
		RequiresSink: "", // No external sink required - emulates deserialization behavior
		ValidVariants: map[string][]string{
			"format": {"auto", "java", "php", "python_pickle", "dotnet"},
			"filter": {"none", "basic_signature", "basic_class", "php_basic", "allowlist", "blocklist"},
		},
	}
}

// DeserializationResult represents the result of processing a serialized payload
type DeserializationResult struct {
	Format       string                 `json:"format"`
	Detected     bool                   `json:"detected"`
	PayloadType  string                 `json:"payload_type,omitempty"`
	ClassName    string                 `json:"class_name,omitempty"`
	Properties   map[string]interface{} `json:"properties,omitempty"`
	RawPayload   string                 `json:"raw_payload,omitempty"`
	Decoded      string                 `json:"decoded,omitempty"`
	Warning      string                 `json:"warning,omitempty"`
	Exploitable  bool                   `json:"exploitable"`
	GadgetChain  string                 `json:"gadget_chain,omitempty"`
	SimulatedCmd string                 `json:"simulated_command,omitempty"`
}

// Handle processes the request and emulates deserialization behavior
func (m *Deserialization) Handle(ctx *HandlerContext) (*Result, error) {
	// Get configuration
	format := ctx.GetConfigString("format", "auto")
	filter := ctx.GetConfigString("filter", "none")
	showDecoded := ctx.GetConfigBool("show_decoded", true)
	emulateExec := ctx.GetConfigBool("emulate_execution", true)

	input := ctx.Input

	// Apply filter before processing
	if blocked, reason := applyDeserializationFilter(input, filter, ctx.Config); blocked {
		return &Result{
			Data: map[string]interface{}{
				"error":   "blocked",
				"reason":  reason,
				"blocked": true,
			},
		}, nil
	}

	// Detect and process serialized data
	result := processSerializedData(input, format, showDecoded, emulateExec)

	return NewResult(result), nil
}

// processSerializedData detects the format and processes serialized data
func processSerializedData(input, format string, showDecoded, emulateExec bool) *DeserializationResult {
	result := &DeserializationResult{
		RawPayload: input,
	}

	// Try to decode base64 if input looks like base64
	decoded := input
	if isBase64(input) {
		decodedBytes, err := base64.StdEncoding.DecodeString(input)
		if err == nil {
			decoded = string(decodedBytes)
			if showDecoded {
				result.Decoded = decoded
			}
		}
	}

	// Auto-detect or use specified format
	detectedFormat := format
	if format == "auto" {
		detectedFormat = detectSerializationFormat(decoded)
	}

	result.Format = detectedFormat

	switch detectedFormat {
	case "java":
		processJavaSerialized(result, decoded, emulateExec)
	case "php":
		processPHPSerialized(result, decoded, emulateExec)
	case "python_pickle":
		processPythonPickle(result, decoded, emulateExec)
	case "dotnet":
		processDotNetSerialized(result, decoded, emulateExec)
	default:
		result.Detected = false
		result.Warning = "Unknown or unsupported serialization format"
	}

	return result
}

// detectSerializationFormat auto-detects the serialization format
func detectSerializationFormat(data string) string {
	// Java serialized object signature: 0xACED (magic bytes)
	if strings.HasPrefix(data, "\xac\xed") || strings.Contains(data, "\xac\xed") {
		return "java"
	}
	// Check for common Java gadget chain patterns
	if strings.Contains(data, "org.apache.commons.collections") ||
		strings.Contains(data, "ysoserial") ||
		strings.Contains(data, "java.lang.Runtime") ||
		strings.Contains(data, "java.io.ObjectInputStream") ||
		strings.Contains(data, "org.springframework") ||
		strings.Contains(data, "com.sun.org.apache") ||
		strings.Contains(data, "org.hibernate") ||
		strings.Contains(data, "com.mchange.v2.c3p0") ||
		strings.Contains(data, "org.jboss") ||
		strings.Contains(data, "bsh.Interpreter") ||
		strings.Contains(data, "groovy.util") ||
		strings.Contains(data, "rO0AB") { // Base64 of Java magic bytes
		return "java"
	}

	// PHP serialized format: type:value pattern
	phpPattern := regexp.MustCompile(`^[OasidbN]:\d+:`)
	if phpPattern.MatchString(data) {
		return "php"
	}
	// Check for common PHP object patterns
	if strings.Contains(data, "O:") && strings.Contains(data, "\"") {
		return "php"
	}

	// Python Pickle signatures
	if strings.HasPrefix(data, "\x80") || // Protocol 2+
		strings.HasPrefix(data, "cos\n") || // Protocol 0
		strings.HasPrefix(data, "(dp") || // Dict protocol 0
		strings.Contains(data, "cposix\nsystem") ||
		strings.Contains(data, "cos\nsystem") ||
		strings.Contains(data, "__reduce__") {
		return "python_pickle"
	}

	// .NET BinaryFormatter signature
	if strings.HasPrefix(data, "\x00\x01\x00\x00\x00") {
		return "dotnet"
	}
	if strings.Contains(data, "System.") && strings.Contains(data, "Version=") {
		return "dotnet"
	}
	// Check for known .NET gadget chain patterns
	dotnetPatterns := []string{
		"System.Windows.Data.ObjectDataProvider",
		"System.Diagnostics.Process",
		"System.Runtime.Remoting",
		"Microsoft.VisualStudio.Text.Formatting",
		"System.Security.Claims.ClaimsIdentity",
		"System.Data.Services.Internal",
		"System.Configuration.Install.AssemblyInstaller",
		"System.Activities.Presentation",
		"System.Windows.ResourceDictionary",
	}
	for _, pattern := range dotnetPatterns {
		if strings.Contains(data, pattern) {
			return "dotnet"
		}
	}

	return "unknown"
}

// processJavaSerialized processes Java serialized objects
func processJavaSerialized(result *DeserializationResult, data string, emulateExec bool) {
	result.Detected = true
	result.Format = "java"

	// Check for common dangerous gadget chains
	gadgetChains := map[string]string{
		"org.apache.commons.collections.functors.InvokerTransformer": "CommonsCollections",
		"org.apache.commons.collections4":                            "CommonsCollections4",
		"org.springframework.beans":                                  "Spring",
		"com.sun.org.apache.xalan":                                   "Jdk7u21",
		"java.lang.Runtime.getRuntime":                               "Runtime.exec",
		"javax.management":                                           "JMX",
		"org.hibernate":                                              "Hibernate",
		"com.mchange.v2.c3p0":                                        "C3P0",
		"org.jboss":                                                  "JBoss",
		"bsh.Interpreter":                                            "BeanShell",
		"clojure.core":                                               "Clojure",
		"groovy.util":                                                "Groovy",
		"org.codehaus.groovy.runtime":                                "Groovy",
		"com.alibaba.fastjson":                                       "Fastjson",
		"org.apache.wicket":                                          "Wicket",
	}

	for pattern, chain := range gadgetChains {
		if strings.Contains(data, pattern) {
			result.Exploitable = true
			result.GadgetChain = chain
			result.PayloadType = "gadget_chain"
			result.Warning = fmt.Sprintf("Dangerous gadget chain detected: %s", chain)
			break
		}
	}

	// Try to extract class name
	result.ClassName = extractJavaClassName(data)

	// Extract potential command if present
	if emulateExec {
		cmd := extractCommand(data)
		if cmd != "" {
			result.SimulatedCmd = cmd
			result.Exploitable = true
			result.Warning = fmt.Sprintf("Command execution payload detected: %s", cmd)
		}
	}

	if !result.Exploitable {
		result.Warning = "Java serialized object detected - potential deserialization vulnerability"
		result.PayloadType = "serialized_object"
	}
}

// processPHPSerialized processes PHP serialized objects
func processPHPSerialized(result *DeserializationResult, data string, emulateExec bool) {
	result.Detected = true
	result.Format = "php"

	// Parse PHP serialized format
	props := parsePHPSerialized(data)
	result.Properties = props

	// Extract class name from O:length:"classname" pattern
	classPattern := regexp.MustCompile(`O:(\d+):"([^"]+)"`)
	if matches := classPattern.FindStringSubmatch(data); len(matches) > 2 {
		result.ClassName = matches[2]
	}

	// Check for dangerous PHP magic methods / patterns
	dangerousPatterns := []string{
		"__wakeup",
		"__destruct",
		"__toString",
		"__call",
		"system",
		"exec",
		"shell_exec",
		"passthru",
		"popen",
		"proc_open",
		"eval",
		"assert",
		"file_get_contents",
		"file_put_contents",
		"include",
		"require",
		"unserialize",
		"Guzzle",
		"Monolog",
		"PHPUnit",
		"Doctrine",
		"Symfony",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(data, pattern) {
			result.Exploitable = true
			result.PayloadType = "php_object_injection"
			result.Warning = fmt.Sprintf("Dangerous PHP pattern detected: %s", pattern)
			break
		}
	}

	// Extract potential command
	if emulateExec {
		cmd := extractCommand(data)
		if cmd != "" {
			result.SimulatedCmd = cmd
			result.Exploitable = true
		}
	}

	if !result.Exploitable {
		result.Warning = "PHP serialized object detected - potential object injection vulnerability"
		result.PayloadType = "serialized_object"
	}
}

// processPythonPickle processes Python pickle payloads
func processPythonPickle(result *DeserializationResult, data string, emulateExec bool) {
	result.Detected = true
	result.Format = "python_pickle"

	// Check for dangerous pickle patterns
	dangerousPatterns := []string{
		"os.system",
		"subprocess",
		"commands.getoutput",
		"cposix\nsystem",
		"cos\nsystem",
		"__reduce__",
		"__reduce_ex__",
		"eval",
		"exec",
		"compile",
		"builtins",
		"__import__",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(data, pattern) {
			result.Exploitable = true
			result.PayloadType = "pickle_rce"
			result.Warning = fmt.Sprintf("Dangerous pickle pattern detected: %s", pattern)
			break
		}
	}

	if emulateExec {
		cmd := extractCommand(data)
		if cmd != "" {
			result.SimulatedCmd = cmd
			result.Exploitable = true
		}
	}

	if !result.Exploitable {
		result.Warning = "Python pickle detected - potential code execution vulnerability"
		result.PayloadType = "pickle_object"
	}
}

// processDotNetSerialized processes .NET serialized objects
func processDotNetSerialized(result *DeserializationResult, data string, emulateExec bool) {
	result.Detected = true
	result.Format = "dotnet"

	// Check for dangerous .NET patterns
	dangerousPatterns := map[string]string{
		"System.Windows.Data.ObjectDataProvider":                             "ObjectDataProvider",
		"System.Diagnostics.Process":                                         "Process.Start",
		"System.Runtime.Remoting":                                            "Remoting",
		"Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties": "TextFormattingRunProperties",
		"System.Security.Claims.ClaimsIdentity":                              "ClaimsIdentity",
		"System.Data.Services.Internal.ExpandedWrapper":                      "ExpandedWrapper",
		"System.Xml.XmlDocument":                                             "XmlDocument",
		"System.Configuration.Install.AssemblyInstaller":                     "AssemblyInstaller",
		"System.Activities.Presentation.WorkflowDesigner":                    "WorkflowDesigner",
		"System.Windows.ResourceDictionary":                                  "ResourceDictionary",
		"System.IO.FileInfo":                                                 "FileInfo",
	}

	for pattern, chain := range dangerousPatterns {
		if strings.Contains(data, pattern) {
			result.Exploitable = true
			result.GadgetChain = chain
			result.PayloadType = "dotnet_gadget"
			result.Warning = fmt.Sprintf("Dangerous .NET gadget chain detected: %s", chain)
			break
		}
	}

	if emulateExec {
		cmd := extractCommand(data)
		if cmd != "" {
			result.SimulatedCmd = cmd
			result.Exploitable = true
		}
	}

	if !result.Exploitable {
		result.Warning = ".NET serialized object detected - potential deserialization vulnerability"
		result.PayloadType = "binary_formatter"
	}
}

// parsePHPSerialized parses PHP serialized data and extracts properties
func parsePHPSerialized(data string) map[string]interface{} {
	props := make(map[string]interface{})

	// Simple property extraction for s:length:"key";s:length:"value"
	propPattern := regexp.MustCompile(`s:\d+:"([^"]+)";s:\d+:"([^"]+)"`)
	matches := propPattern.FindAllStringSubmatch(data, -1)
	for _, match := range matches {
		if len(match) > 2 {
			props[match[1]] = match[2]
		}
	}

	// Extract integer properties
	intPattern := regexp.MustCompile(`s:\d+:"([^"]+)";i:(\d+)`)
	intMatches := intPattern.FindAllStringSubmatch(data, -1)
	for _, match := range intMatches {
		if len(match) > 2 {
			props[match[1]] = match[2]
		}
	}

	return props
}

// extractJavaClassName extracts class name from Java serialized data
func extractJavaClassName(data string) string {
	// Look for common class name patterns in serialized data
	patterns := []string{
		`L([a-zA-Z0-9_/]+);`,        // Binary format
		`([a-z]+\.)+[A-Z][a-zA-Z]+`, // Dot notation
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if match := re.FindString(data); match != "" {
			return strings.ReplaceAll(match, "/", ".")
		}
	}
	return "unknown"
}

// extractCommand extracts potential command from payload
func extractCommand(data string) string {
	// Common command patterns
	cmdPatterns := []string{
		`(?:exec|system|shell_exec|passthru|popen)\s*\(\s*['"]([^'"]+)['"]`,
		`(?:cmd\.exe|/bin/sh|/bin/bash|powershell)[^\s]*\s+[/-]c\s+['"]?([^'";\)]+)`,
		`Runtime\.getRuntime\(\)\.exec\s*\(\s*['"]([^'"]+)['"]`,
		`(?:calc\.exe|notepad\.exe|whoami|id|cat\s+/etc/passwd|net\s+user)`,
		`ProcessBuilder.*?\["([^"]+)"`,
	}

	for _, pattern := range cmdPatterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(data); len(matches) > 0 {
			if len(matches) > 1 {
				return matches[1]
			}
			return matches[0]
		}
	}
	return ""
}

// isBase64 checks if input looks like base64 encoded data
func isBase64(s string) bool {
	if len(s) < 4 {
		return false
	}
	// Check if contains only base64 characters
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
	return base64Pattern.MatchString(strings.TrimSpace(s))
}

// applyDeserializationFilter applies filtering based on configuration
func applyDeserializationFilter(input, filter string, cfg map[string]interface{}) (bool, string) {
	switch filter {
	case "none":
		// No filtering - fully vulnerable
		return false, ""

	case "basic_signature":
		// Block obvious Java serialization magic bytes
		if strings.Contains(input, "\xac\xed") || strings.Contains(input, "rO0AB") {
			return true, "Java serialization signature blocked"
		}
		return false, ""

	case "basic_class":
		// Block known dangerous class names
		blockedClasses := []string{
			"org.apache.commons.collections",
			"org.springframework",
			"com.sun.org.apache",
			"java.lang.Runtime",
			"ProcessBuilder",
		}
		lowerInput := strings.ToLower(input)
		for _, class := range blockedClasses {
			if strings.Contains(lowerInput, strings.ToLower(class)) {
				return true, fmt.Sprintf("Blocked class pattern: %s", class)
			}
		}
		return false, ""

	case "php_basic":
		// Block PHP object serialization
		if strings.HasPrefix(input, "O:") || strings.Contains(input, "O:") {
			return true, "PHP object serialization blocked"
		}
		return false, ""

	case "allowlist":
		// Only allow specific classes (get from config)
		allowedClasses := getStringSlice(cfg, "allowed_classes", []string{})
		if len(allowedClasses) == 0 {
			return true, "No classes in allowlist"
		}
		for _, allowed := range allowedClasses {
			if strings.Contains(input, allowed) {
				return false, ""
			}
		}
		return true, "Class not in allowlist"

	case "blocklist":
		// Block specific patterns
		blockedPatterns := getStringSlice(cfg, "blocked_patterns", []string{})
		for _, pattern := range blockedPatterns {
			if strings.Contains(input, pattern) {
				return true, fmt.Sprintf("Blocked pattern: %s", pattern)
			}
		}
		return false, ""

	default:
		return false, ""
	}
}
