package modules

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// XXE implements the xxe (XML External Entity) vulnerability module
type XXE struct{}

// init registers the module
func init() {
	Register(&XXE{})
}

// Info returns module metadata
func (m *XXE) Info() ModuleInfo {
	return ModuleInfo{
		Name:        "xxe",
		Description: "XML External Entity (XXE) vulnerability that allows reading files, SSRF, and denial of service through malicious XML",
		SupportedPlacements: []string{
			"query_param",
			"form_field",
			"json_field",
			"header",
			"cookie",
		},
		RequiresSink: "", // Can optionally use filesystem sink for file reading
		ValidVariants: map[string][]string{
			"filter": {"none", "basic_doctype", "basic_entity", "external_entities"},
		},
	}
}

// XXEResult represents the result of processing an XML payload
type XXEResult struct {
	Parsed           bool                   `json:"parsed"`
	DetectedEntities []string               `json:"detected_entities,omitempty"`
	ExternalEntities []ExternalEntityInfo   `json:"external_entities,omitempty"`
	ResolvedContent  map[string]string      `json:"resolved_content,omitempty"`
	RootElement      string                 `json:"root_element,omitempty"`
	Elements         []string               `json:"elements,omitempty"`
	Attributes       map[string]string      `json:"attributes,omitempty"`
	RawXML           string                 `json:"raw_xml,omitempty"`
	Decoded          string                 `json:"decoded,omitempty"`
	Warning          string                 `json:"warning,omitempty"`
	Exploitable      bool                   `json:"exploitable"`
	AttackType       string                 `json:"attack_type,omitempty"`
	SimulatedOutput  string                 `json:"simulated_output,omitempty"`
	Error            string                 `json:"error,omitempty"`
	ParsedData       map[string]interface{} `json:"parsed_data,omitempty"`
}

// ExternalEntityInfo holds information about a detected external entity
type ExternalEntityInfo struct {
	Name      string `json:"name"`
	Type      string `json:"type"` // SYSTEM, PUBLIC, PARAMETER
	URI       string `json:"uri,omitempty"`
	Protocol  string `json:"protocol,omitempty"` // file, http, https, ftp, php, expect, etc.
	Dangerous bool   `json:"dangerous"`
	Reason    string `json:"reason,omitempty"`
}

// Handle processes the request and emulates XXE behavior
func (m *XXE) Handle(ctx *HandlerContext) (*Result, error) {
	// Get configuration
	filter := ctx.GetConfigString("filter", "none")
	showDecoded := ctx.GetConfigBool("show_decoded", true)
	emulateResolution := ctx.GetConfigBool("emulate_resolution", true)
	allowFileRead := ctx.GetConfigBool("allow_file_read", true)
	maxDepth := ctx.GetConfigInt("max_entity_depth", 10)

	input := ctx.Input

	// Apply filter before processing
	if blocked, reason := applyXXEFilter(input, filter, ctx.Config); blocked {
		return &Result{
			Data: map[string]interface{}{
				"error":   "blocked",
				"reason":  reason,
				"blocked": true,
			},
		}, nil
	}

	// Process the XML input
	result := processXMLPayload(input, showDecoded, emulateResolution, allowFileRead, maxDepth, ctx)

	return NewResult(result), nil
}

// processXMLPayload processes the XML input and detects XXE patterns
func processXMLPayload(input string, showDecoded, emulateResolution, allowFileRead bool, maxDepth int, ctx *HandlerContext) *XXEResult {
	result := &XXEResult{
		RawXML:           input,
		DetectedEntities: []string{},
		ExternalEntities: []ExternalEntityInfo{},
		ResolvedContent:  make(map[string]string),
		ParsedData:       make(map[string]interface{}),
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

	// Check if it's valid XML
	if !isXML(decoded) {
		result.Parsed = false
		result.Error = "Input is not valid XML"
		return result
	}

	// Parse and analyze XML
	result.Parsed = true

	// Detect DOCTYPE and entities
	detectDOCTYPEEntities(result, decoded)

	// Detect external entities
	detectExternalEntities(result, decoded)

	// Determine attack type
	determineAttackType(result)

	// Try to parse XML structure
	parseXMLStructure(result, decoded)

	// Emulate entity resolution if enabled
	if emulateResolution && result.Exploitable {
		emulateEntityResolution(result, decoded, allowFileRead, ctx)
	}

	// Add warning if exploitable patterns detected
	if result.Exploitable {
		result.Warning = fmt.Sprintf("XXE vulnerability detected: %s attack pattern found", result.AttackType)
	}

	return result
}

// isXML checks if the input looks like XML
func isXML(input string) bool {
	input = strings.TrimSpace(input)
	// Check for XML declaration or root element
	if strings.HasPrefix(input, "<?xml") || strings.HasPrefix(input, "<!DOCTYPE") || strings.HasPrefix(input, "<") {
		return true
	}
	return false
}

// detectDOCTYPEEntities detects DOCTYPE declarations and entity definitions
func detectDOCTYPEEntities(result *XXEResult, xml string) {
	// Detect DOCTYPE
	doctypePattern := regexp.MustCompile(`(?is)<!DOCTYPE\s+(\w+)\s*\[([^\]]*)\]`)
	if matches := doctypePattern.FindStringSubmatch(xml); len(matches) > 0 {
		result.RootElement = matches[1]

		// Extract internal subset
		internalSubset := matches[2]

		// Find all ENTITY declarations
		entityPattern := regexp.MustCompile(`(?i)<!ENTITY\s+(%?\s*)(\w+)\s+(?:SYSTEM\s+["']([^"']+)["']|PUBLIC\s+["'][^"']*["']\s+["']([^"']+)["']|["']([^"']+)["'])`)
		entityMatches := entityPattern.FindAllStringSubmatch(internalSubset, -1)

		for _, match := range entityMatches {
			entityName := match[2]
			isParameter := strings.TrimSpace(match[1]) == "%"

			result.DetectedEntities = append(result.DetectedEntities, entityName)

			// Determine if it's an external entity
			if match[3] != "" || match[4] != "" {
				uri := match[3]
				if uri == "" {
					uri = match[4]
				}

				entityType := "SYSTEM"
				if match[4] != "" {
					entityType = "PUBLIC"
				}
				if isParameter {
					entityType = "PARAMETER"
				}

				entityInfo := ExternalEntityInfo{
					Name:     entityName,
					Type:     entityType,
					URI:      uri,
					Protocol: detectProtocol(uri),
				}

				// Check if dangerous
				entityInfo.Dangerous, entityInfo.Reason = isEntityDangerous(entityInfo)

				result.ExternalEntities = append(result.ExternalEntities, entityInfo)

				if entityInfo.Dangerous {
					result.Exploitable = true
				}
			}
		}
	}

	// Also check for standalone DOCTYPE with SYSTEM
	standaloneDoctype := regexp.MustCompile(`(?i)<!DOCTYPE\s+\w+\s+SYSTEM\s+["']([^"']+)["']`)
	if matches := standaloneDoctype.FindStringSubmatch(xml); len(matches) > 0 {
		entityInfo := ExternalEntityInfo{
			Name:     "DOCTYPE",
			Type:     "SYSTEM",
			URI:      matches[1],
			Protocol: detectProtocol(matches[1]),
		}
		entityInfo.Dangerous, entityInfo.Reason = isEntityDangerous(entityInfo)
		result.ExternalEntities = append(result.ExternalEntities, entityInfo)
		if entityInfo.Dangerous {
			result.Exploitable = true
		}
	}
}

// detectExternalEntities looks for various XXE patterns
func detectExternalEntities(result *XXEResult, xmlContent string) {
	// Common XXE patterns
	patterns := []struct {
		name    string
		pattern *regexp.Regexp
		reason  string
	}{
		{
			name:    "file_protocol",
			pattern: regexp.MustCompile(`(?i)file://[^"'\s>]+`),
			reason:  "Local file access via file:// protocol",
		},
		{
			name:    "php_filter",
			pattern: regexp.MustCompile(`(?i)php://filter[^"'\s>]*`),
			reason:  "PHP filter wrapper for file reading",
		},
		{
			name:    "php_expect",
			pattern: regexp.MustCompile(`(?i)expect://[^"'\s>]+`),
			reason:  "PHP expect wrapper for command execution",
		},
		{
			name:    "php_input",
			pattern: regexp.MustCompile(`(?i)php://input`),
			reason:  "PHP input stream",
		},
		{
			name:    "data_protocol",
			pattern: regexp.MustCompile(`(?i)data://[^"'\s>]+`),
			reason:  "Data URI protocol",
		},
		{
			name:    "http_ssrf",
			pattern: regexp.MustCompile(`(?i)https?://[^"'\s>]+`),
			reason:  "HTTP/HTTPS request (potential SSRF)",
		},
		{
			name:    "ftp_protocol",
			pattern: regexp.MustCompile(`(?i)ftp://[^"'\s>]+`),
			reason:  "FTP protocol access",
		},
		{
			name:    "gopher_protocol",
			pattern: regexp.MustCompile(`(?i)gopher://[^"'\s>]+`),
			reason:  "Gopher protocol (advanced SSRF)",
		},
		{
			name:    "jar_protocol",
			pattern: regexp.MustCompile(`(?i)jar:[^"'\s>]+`),
			reason:  "JAR protocol for Java environments",
		},
		{
			name:    "netdoc_protocol",
			pattern: regexp.MustCompile(`(?i)netdoc://[^"'\s>]+`),
			reason:  "Netdoc protocol for Java environments",
		},
	}

	for _, p := range patterns {
		if matches := p.pattern.FindAllString(xmlContent, -1); len(matches) > 0 {
			result.Exploitable = true
			for _, match := range matches {
				// Check if already added
				found := false
				for _, existing := range result.ExternalEntities {
					if existing.URI == match {
						found = true
						break
					}
				}
				if !found {
					result.ExternalEntities = append(result.ExternalEntities, ExternalEntityInfo{
						Name:      p.name,
						Type:      "PATTERN",
						URI:       match,
						Protocol:  p.name,
						Dangerous: true,
						Reason:    p.reason,
					})
				}
			}
		}
	}

	// Detect billion laughs / entity expansion attacks
	billionLaughsPattern := regexp.MustCompile(`(?i)<!ENTITY\s+\w+\s+["'](&\w+;)+["']`)
	if billionLaughsPattern.MatchString(xmlContent) {
		result.Exploitable = true
		result.ExternalEntities = append(result.ExternalEntities, ExternalEntityInfo{
			Name:      "entity_expansion",
			Type:      "DOS",
			Dangerous: true,
			Reason:    "Entity expansion attack (Billion Laughs) detected",
		})
	}

	// Detect parameter entity injection
	paramEntityPattern := regexp.MustCompile(`(?i)<!ENTITY\s+%\s+\w+`)
	if paramEntityPattern.MatchString(xmlContent) {
		result.Exploitable = true
		result.ExternalEntities = append(result.ExternalEntities, ExternalEntityInfo{
			Name:      "parameter_entity",
			Type:      "PARAMETER",
			Dangerous: true,
			Reason:    "Parameter entity detected (potential blind XXE)",
		})
	}
}

// detectProtocol extracts the protocol from a URI
func detectProtocol(uri string) string {
	if idx := strings.Index(uri, "://"); idx > 0 {
		return strings.ToLower(uri[:idx])
	}
	if strings.HasPrefix(strings.ToLower(uri), "jar:") {
		return "jar"
	}
	return "unknown"
}

// isEntityDangerous determines if an external entity is dangerous
func isEntityDangerous(entity ExternalEntityInfo) (bool, string) {
	protocol := strings.ToLower(entity.Protocol)
	uri := strings.ToLower(entity.URI)

	dangerousProtocols := map[string]string{
		"file":   "Local file system access",
		"php":    "PHP wrapper execution",
		"expect": "Command execution via expect",
		"gopher": "Advanced SSRF via Gopher protocol",
		"jar":    "Java archive access",
		"netdoc": "Java Netdoc protocol",
		"ftp":    "FTP file transfer",
		"data":   "Data URI injection",
	}

	if reason, ok := dangerousProtocols[protocol]; ok {
		return true, reason
	}

	// HTTP(S) is dangerous if pointing to internal resources
	if protocol == "http" || protocol == "https" {
		internalIndicators := []string{
			"localhost", "127.0.0.1", "0.0.0.0",
			"169.254.", "10.", "192.168.", "172.16.",
			"[::1]", "internal", "intranet",
		}
		for _, indicator := range internalIndicators {
			if strings.Contains(uri, indicator) {
				return true, "SSRF to internal resource"
			}
		}
		return true, "Potential SSRF via external request"
	}

	return false, ""
}

// determineAttackType determines the type of XXE attack
func determineAttackType(result *XXEResult) {
	if !result.Exploitable {
		return
	}

	// Check for specific attack patterns
	for _, entity := range result.ExternalEntities {
		protocol := strings.ToLower(entity.Protocol)
		switch {
		case protocol == "file" || protocol == "ftp" || strings.Contains(entity.URI, "php://filter"):
			result.AttackType = "file_disclosure"
		case strings.Contains(entity.URI, "expect://"):
			result.AttackType = "remote_code_execution"
		case entity.Type == "DOS":
			result.AttackType = "denial_of_service"
		case entity.Type == "PARAMETER":
			result.AttackType = "blind_xxe"
		case protocol == "http" || protocol == "https" || protocol == "gopher":
			if result.AttackType == "" {
				result.AttackType = "ssrf"
			}
		}
	}

	if result.AttackType == "" {
		result.AttackType = "generic_xxe"
	}
}

// parseXMLStructure parses the XML to extract structure information
func parseXMLStructure(result *XXEResult, xmlContent string) {
	decoder := xml.NewDecoder(strings.NewReader(xmlContent))
	decoder.Strict = false
	decoder.AutoClose = xml.HTMLAutoClose
	decoder.Entity = xml.HTMLEntity

	var elements []string
	attributes := make(map[string]string)

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// XML parsing error - this is expected with malicious XML
			break
		}

		switch t := token.(type) {
		case xml.StartElement:
			elements = append(elements, t.Name.Local)
			if result.RootElement == "" {
				result.RootElement = t.Name.Local
			}
			for _, attr := range t.Attr {
				key := fmt.Sprintf("%s.%s", t.Name.Local, attr.Name.Local)
				attributes[key] = attr.Value
			}
		}
	}

	result.Elements = elements
	result.Attributes = attributes
}

// emulateEntityResolution simulates what would happen if entities were resolved
func emulateEntityResolution(result *XXEResult, xmlContent string, allowFileRead bool, ctx *HandlerContext) {
	for _, entity := range result.ExternalEntities {
		switch strings.ToLower(entity.Protocol) {
		case "file":
			// Simulate file reading
			filePath := strings.TrimPrefix(strings.ToLower(entity.URI), "file://")
			filePath = strings.TrimPrefix(filePath, "/")

			// Try common file paths for demonstration
			simulatedContent := simulateFileRead(filePath, allowFileRead, ctx)
			if simulatedContent != "" {
				result.ResolvedContent[entity.Name] = simulatedContent
				result.SimulatedOutput = simulatedContent
			}

		case "http", "https":
			// Simulate HTTP request
			result.ResolvedContent[entity.Name] = fmt.Sprintf("[SSRF: Would make request to %s]", entity.URI)

		case "php":
			// Simulate PHP filter
			if strings.Contains(entity.URI, "php://filter") {
				result.ResolvedContent[entity.Name] = "[PHP Filter: Would read file with encoding transformation]"
			}

		case "expect":
			// Simulate expect command execution
			cmdPattern := regexp.MustCompile(`expect://(.+)`)
			if matches := cmdPattern.FindStringSubmatch(entity.URI); len(matches) > 1 {
				result.ResolvedContent[entity.Name] = fmt.Sprintf("[RCE: Would execute command: %s]", matches[1])
			}

		case "gopher":
			// Simulate Gopher SSRF
			result.ResolvedContent[entity.Name] = fmt.Sprintf("[Gopher SSRF: Would send raw request to %s]", entity.URI)
		}
	}

	// Check for entity references in XML content and simulate expansion
	entityRefPattern := regexp.MustCompile(`&(\w+);`)
	if matches := entityRefPattern.FindAllStringSubmatch(xmlContent, -1); len(matches) > 0 {
		for _, match := range matches {
			entityName := match[1]
			if content, ok := result.ResolvedContent[entityName]; ok {
				result.ParsedData[entityName] = content
			}
		}
	}
}

// simulateFileRead simulates reading a file for demonstration
func simulateFileRead(filePath string, allowFileRead bool, ctx *HandlerContext) string {
	// Normalize path
	filePath = strings.ReplaceAll(filePath, "\\", "/")

	// Common sensitive files that would typically be targeted
	sensitiveFiles := map[string]string{
		"etc/passwd":         "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
		"etc/shadow":         "[Permission denied - requires root]",
		"etc/hosts":          "127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback",
		"windows/win.ini":    "[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1",
		"windows/system.ini": "[boot]\n[386Enh]\n[drivers]\n[keyboard]",
		"proc/self/environ":  "PATH=/usr/local/sbin:/usr/local/bin\nHOSTNAME=vulnerable-server\nHOME=/var/www",
		".htaccess":          "RewriteEngine On\nRewriteRule ^(.*)$ index.php [QSA,L]",
		"web.xml":            "<?xml version=\"1.0\"?>\n<web-app>\n<servlet>\n<servlet-name>app</servlet-name>\n</servlet>\n</web-app>",
	}

	// Check for exact or partial matches
	for path, content := range sensitiveFiles {
		if strings.Contains(filePath, path) || strings.HasSuffix(filePath, path) {
			return content
		}
	}

	// If we have a filesystem sink and file reading is allowed, try to read actual file
	if allowFileRead && ctx != nil && ctx.Sinks != nil && ctx.Sinks.Filesystem != nil {
		content, err := ctx.Sinks.Filesystem.Read(filePath)
		if err == nil {
			return content
		}
	}

	return fmt.Sprintf("[File not found or access denied: %s]", filePath)
}

// applyXXEFilter applies security filtering based on configuration
func applyXXEFilter(input, filter string, cfg map[string]interface{}) (bool, string) {
	switch filter {
	case "none":
		// No filtering - fully vulnerable
		return false, ""

	case "basic_doctype":
		// Block DOCTYPE declarations
		if strings.Contains(strings.ToLower(input), "<!doctype") {
			return true, "DOCTYPE declarations are not allowed"
		}
		return false, ""

	case "basic_entity":
		// Block ENTITY declarations
		if strings.Contains(strings.ToLower(input), "<!entity") {
			return true, "ENTITY declarations are not allowed"
		}
		return false, ""

	case "external_entities":
		// Block external entity patterns
		patterns := []string{"system", "public", "file://", "http://", "https://", "ftp://", "php://", "expect://"}
		lowerInput := strings.ToLower(input)
		for _, pattern := range patterns {
			if strings.Contains(lowerInput, pattern) {
				return true, fmt.Sprintf("External entity pattern '%s' is not allowed", pattern)
			}
		}
		return false, ""

	default:
		return false, ""
	}
}
