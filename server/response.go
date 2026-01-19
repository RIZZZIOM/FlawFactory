package server

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
)

// ResponseBuilder handles formatting and sending HTTP responses
type ResponseBuilder struct{}

// NewResponseBuilder creates a new response builder
func NewResponseBuilder() *ResponseBuilder {
	return &ResponseBuilder{}
}

// ResponseData holds the data to be sent in the response
type ResponseData struct {
	Data  interface{} `json:"data,omitempty" xml:"data,omitempty"`
	Error string      `json:"error,omitempty" xml:"error,omitempty"`
}

// DebugInfo holds debug information for error responses
type DebugInfo struct {
	Message   string `json:"message" xml:"message"`
	Module    string `json:"module,omitempty" xml:"module,omitempty"`
	Placement string `json:"placement,omitempty" xml:"placement,omitempty"`
	Param     string `json:"param,omitempty" xml:"param,omitempty"`
}

// ErrorResponse is the structure for error responses with debug info
type ErrorResponse struct {
	Error string    `json:"error" xml:"error"`
	Debug DebugInfo `json:"debug" xml:"debug"`
}

// Send sends a successful response in the specified format
func (rb *ResponseBuilder) Send(w http.ResponseWriter, responseType string, data interface{}) {
	rb.SendWithStatus(w, responseType, http.StatusOK, data)
}

// SendWithStatus sends a response with a custom status code
func (rb *ResponseBuilder) SendWithStatus(w http.ResponseWriter, responseType string, statusCode int, data interface{}) {
	switch responseType {
	case "json":
		rb.sendJSON(w, statusCode, ResponseData{Data: data})
	case "html":
		rb.sendHTML(w, statusCode, data)
	case "xml":
		rb.sendXML(w, statusCode, ResponseData{Data: data})
	case "text":
		rb.sendText(w, statusCode, data)
	default:
		// Default to JSON
		rb.sendJSON(w, statusCode, ResponseData{Data: data})
	}
}

// SendError sends an error response with debug information (always enabled)
func (rb *ResponseBuilder) SendError(w http.ResponseWriter, responseType string, statusCode int, err string, debug DebugInfo) {
	errResp := ErrorResponse{
		Error: err,
		Debug: debug,
	}

	switch responseType {
	case "json":
		rb.sendJSON(w, statusCode, errResp)
	case "html":
		rb.sendErrorHTML(w, statusCode, errResp)
	case "xml":
		rb.sendXML(w, statusCode, errResp)
	case "text":
		rb.sendErrorText(w, statusCode, errResp)
	default:
		rb.sendJSON(w, statusCode, errResp)
	}
}

// SendRaw sends raw data with the appropriate content type
func (rb *ResponseBuilder) SendRaw(w http.ResponseWriter, responseType string, statusCode int, data interface{}) {
	switch responseType {
	case "json":
		rb.sendJSON(w, statusCode, data)
	case "html":
		rb.sendHTML(w, statusCode, data)
	case "xml":
		rb.sendXML(w, statusCode, data)
	case "text":
		rb.sendText(w, statusCode, data)
	default:
		rb.sendJSON(w, statusCode, data)
	}
}

// sendJSON sends a JSON response
func (rb *ResponseBuilder) sendJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		// Fallback if encoding fails
		fmt.Fprintf(w, `{"error":"failed to encode response"}`)
	}
}

// sendHTML sends an HTML response
func (rb *ResponseBuilder) sendHTML(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	// Convert data to string for HTML
	var content string
	switch v := data.(type) {
	case string:
		content = v
	case []byte:
		content = string(v)
	default:
		// For complex types, convert to JSON and wrap in pre tag
		jsonBytes, _ := json.MarshalIndent(v, "", "  ")
		content = fmt.Sprintf("<pre>%s</pre>", string(jsonBytes))
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>FlawFactory Response</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
%s
</body>
</html>`, content)
}

// sendErrorHTML sends an HTML error response
func (rb *ResponseBuilder) sendErrorHTML(w http.ResponseWriter, statusCode int, errResp ErrorResponse) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Error - FlawFactory</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .error { color: #c00; }
        .debug { background: #f4f4f4; padding: 15px; border-radius: 5px; margin-top: 10px; }
        .debug h3 { margin-top: 0; }
        .debug-item { margin: 5px 0; }
        .label { font-weight: bold; }
    </style>
</head>
<body>
    <h1 class="error">Error</h1>
    <p>%s</p>
    <div class="debug">
        <h3>Debug Information</h3>
        <div class="debug-item"><span class="label">Message:</span> %s</div>
        <div class="debug-item"><span class="label">Module:</span> %s</div>
        <div class="debug-item"><span class="label">Placement:</span> %s</div>
        <div class="debug-item"><span class="label">Param:</span> %s</div>
    </div>
</body>
</html>`, errResp.Error, errResp.Debug.Message, errResp.Debug.Module, errResp.Debug.Placement, errResp.Debug.Param)
}

// XMLResponse wraps data for proper XML encoding
type XMLResponse struct {
	XMLName xml.Name    `xml:"response"`
	Data    interface{} `xml:"data,omitempty"`
	Error   string      `xml:"error,omitempty"`
}

// XMLErrorResponse wraps error data for XML encoding
type XMLErrorResponse struct {
	XMLName xml.Name  `xml:"response"`
	Error   string    `xml:"error"`
	Debug   DebugInfo `xml:"debug"`
}

// sendXML sends an XML response
func (rb *ResponseBuilder) sendXML(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(statusCode)

	// Write XML header
	fmt.Fprint(w, xml.Header)

	encoder := xml.NewEncoder(w)
	encoder.Indent("", "  ")

	// Wrap in response element if not already an ErrorResponse
	switch v := data.(type) {
	case ErrorResponse:
		xmlErr := XMLErrorResponse{
			Error: v.Error,
			Debug: v.Debug,
		}
		if err := encoder.Encode(xmlErr); err != nil {
			fmt.Fprintf(w, "<response><error>failed to encode response</error></response>")
		}
	case ResponseData:
		xmlResp := XMLResponse{
			Data:  v.Data,
			Error: v.Error,
		}
		if err := encoder.Encode(xmlResp); err != nil {
			fmt.Fprintf(w, "<response><error>failed to encode response</error></response>")
		}
	default:
		xmlResp := XMLResponse{Data: v}
		if err := encoder.Encode(xmlResp); err != nil {
			fmt.Fprintf(w, "<response><error>failed to encode response</error></response>")
		}
	}
}

// sendText sends a plain text response
func (rb *ResponseBuilder) sendText(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(statusCode)

	switch v := data.(type) {
	case string:
		fmt.Fprint(w, v)
	case []byte:
		w.Write(v)
	default:
		// For complex types, convert to JSON
		jsonBytes, _ := json.MarshalIndent(v, "", "  ")
		w.Write(jsonBytes)
	}
}

// sendErrorText sends a plain text error response
func (rb *ResponseBuilder) sendErrorText(w http.ResponseWriter, statusCode int, errResp ErrorResponse) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(statusCode)

	fmt.Fprintf(w, "ERROR: %s\n\nDEBUG INFO:\n  Message: %s\n  Module: %s\n  Placement: %s\n  Param: %s\n",
		errResp.Error,
		errResp.Debug.Message,
		errResp.Debug.Module,
		errResp.Debug.Placement,
		errResp.Debug.Param)
}

// CombinedResult holds results from multiple vulnerability handlers
type CombinedResult struct {
	Results []ModuleResult `json:"results" xml:"results"`
}

// ModuleResult holds a single module's result
type ModuleResult struct {
	Module     string      `json:"module" xml:"module"`
	Param      string      `json:"param" xml:"param"`
	Data       interface{} `json:"data,omitempty" xml:"data,omitempty"`
	Error      string      `json:"error,omitempty" xml:"error,omitempty"`
	StatusCode int         `json:"-" xml:"-"` // Used internally, not serialized
}

// SendCombined sends a combined response from multiple vulnerability handlers
func (rb *ResponseBuilder) SendCombined(w http.ResponseWriter, responseType string, results []ModuleResult) {
	combined := CombinedResult{Results: results}
	rb.Send(w, responseType, combined)
}
