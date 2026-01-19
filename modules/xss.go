package modules

import (
	"fmt"
	"strings"
)

// XSSReflected implements the xss_reflected vulnerability module
type XSSReflected struct{}

// init registers the module
func init() {
	Register(&XSSReflected{})
}

// Info returns module metadata
func (m *XSSReflected) Info() ModuleInfo {
	return ModuleInfo{
		Name:        "xss_reflected",
		Description: "Reflected Cross-Site Scripting with multiple contexts (body, attribute, script)",
		SupportedPlacements: []string{
			"query_param",
			"path_param",
			"form_field",
			"json_field",
			"header",
		},
		RequiresSink: "", // No sink needed
		ValidVariants: map[string][]string{
			"context":  {"body", "attribute", "script"},
			"encoding": {"none", "incomplete_html", "incomplete_js", "weak_encode"},
		},
	}
}

// Handle processes the request and reflects input
func (m *XSSReflected) Handle(ctx *HandlerContext) (*Result, error) {
	// Get configuration
	context := ctx.GetConfigString("context", "body")
	encoding := ctx.GetConfigString("encoding", "none")
	template := ctx.GetConfigString("template", "")

	input := ctx.Input

	// Apply encoding filter
	input = applyXSSEncoding(input, encoding)

	// Generate output based on context
	var output string

	switch context {
	case "body":
		output = m.handleBodyContext(input, template)
	case "attribute":
		output = m.handleAttributeContext(input, template)
	case "script":
		output = m.handleScriptContext(input, template)
	default:
		output = m.handleBodyContext(input, template)
	}

	result := NewResult(map[string]interface{}{
		"reflected": output,
		"input":     ctx.Input,
		"context":   context,
	})

	// Set raw output for HTML responses
	result.RawOutput = []byte(output)

	return result, nil
}

// handleBodyContext reflects input in HTML body
func (m *XSSReflected) handleBodyContext(input, template string) string {
	if template != "" {
		return strings.ReplaceAll(template, "{input}", input)
	}
	return fmt.Sprintf(`<div class="result">
    <h2>Search Results</h2>
    <p>You searched for: %s</p>
    <p>No results found.</p>
</div>`, input)
}

// handleAttributeContext reflects input in HTML attribute
func (m *XSSReflected) handleAttributeContext(input, template string) string {
	if template != "" {
		return strings.ReplaceAll(template, "{input}", input)
	}
	return fmt.Sprintf(`<div class="result">
    <input type="text" value="%s" class="search-box">
    <img src="/images/search.png" alt="Search for %s">
    <a href="/search?q=%s">Search again</a>
</div>`, input, input, input)
}

// handleScriptContext reflects input in JavaScript
func (m *XSSReflected) handleScriptContext(input, template string) string {
	if template != "" {
		return strings.ReplaceAll(template, "{input}", input)
	}
	return fmt.Sprintf(`<script>
    var searchTerm = '%s';
    var config = {
        query: "%s",
        timestamp: Date.now()
    };
    console.log("Searching for: " + searchTerm);
</script>`, input, input)
}

// applyXSSEncoding applies encoding/filtering to input
func applyXSSEncoding(input, encoding string) string {
	switch encoding {
	case "none":
		// No encoding - fully vulnerable
		return input
	case "incomplete_html":
		// Incomplete HTML encoding - only encodes < and >
		input = strings.ReplaceAll(input, "<", "&lt;")
		input = strings.ReplaceAll(input, ">", "&gt;")
		return input
	case "incomplete_js":
		// Incomplete JS escaping - only escapes single quotes
		input = strings.ReplaceAll(input, "'", "\\'")
		return input
	case "weak_encode":
		// Weak blocklist filter - case-sensitive, can be bypassed with:
		// - Mixed case: <ScRiPt>, <SCRIPT>, <Script>
		// - Alternative tags: <img src=x onerror=alert(1)>, <svg onload=alert(1)>
		input = strings.ReplaceAll(input, "<script>", "")
		input = strings.ReplaceAll(input, "</script>", "")
		input = strings.ReplaceAll(input, "<script", "")
		return input
	default:
		return input
	}
}
