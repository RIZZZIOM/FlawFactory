package server

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
)

// Extractor handles extracting user input from various placements in HTTP requests
type Extractor struct{}

// NewExtractor creates a new extractor instance
func NewExtractor() *Extractor {
	return &Extractor{}
}

// Extract extracts a value from the request based on placement and param name
func (e *Extractor) Extract(r *http.Request, placement, param string) (string, error) {
	switch placement {
	case "query_param":
		return e.extractQueryParam(r, param), nil
	case "path_param":
		return e.extractPathParam(r, param), nil
	case "header":
		return e.extractHeader(r, param), nil
	case "cookie":
		return e.extractCookie(r, param), nil
	case "form_field":
		return e.extractFormField(r, param)
	case "json_field":
		return e.extractJSONField(r, param)
	case "multipart-form":
		return e.extractMultipartForm(r, param)
	default:
		return "", &ExtractionError{
			Placement: placement,
			Param:     param,
			Message:   "unsupported placement type",
		}
	}
}

// extractQueryParam extracts a value from URL query string
func (e *Extractor) extractQueryParam(r *http.Request, param string) string {
	return r.URL.Query().Get(param)
}

// extractPathParam extracts a value from URL path using Go 1.22+ PathValue
func (e *Extractor) extractPathParam(r *http.Request, param string) string {
	return r.PathValue(param)
}

// extractHeader extracts a value from HTTP headers
func (e *Extractor) extractHeader(r *http.Request, param string) string {
	return r.Header.Get(param)
}

// extractCookie extracts a value from cookies
func (e *Extractor) extractCookie(r *http.Request, param string) string {
	cookie, err := r.Cookie(param)
	if err != nil {
		return ""
	}
	// URL-decode the cookie value to handle encoded special characters
	decoded, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return cookie.Value // Return raw value if decoding fails
	}
	return decoded
}

// extractFormField extracts a value from URL-encoded form data
func (e *Extractor) extractFormField(r *http.Request, param string) (string, error) {
	// ParseForm is idempotent and populates r.Form
	if err := r.ParseForm(); err != nil {
		return "", &ExtractionError{
			Placement: "form_field",
			Param:     param,
			Message:   "failed to parse form: " + err.Error(),
		}
	}
	return r.FormValue(param), nil
}

// extractJSONField extracts a value from JSON body
// Supports dot notation for nested fields: "user.profile.name"
func (e *Extractor) extractJSONField(r *http.Request, param string) (string, error) {
	// Read the body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", &ExtractionError{
			Placement: "json_field",
			Param:     param,
			Message:   "failed to read body: " + err.Error(),
		}
	}

	// Parse JSON into a generic map
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", &ExtractionError{
			Placement: "json_field",
			Param:     param,
			Message:   "failed to parse JSON: " + err.Error(),
		}
	}

	// Navigate dot notation path
	value := navigateJSON(data, param)
	return value, nil
}

// navigateJSON navigates a nested JSON structure using dot notation
func navigateJSON(data map[string]interface{}, path string) string {
	parts := strings.Split(path, ".")
	var current interface{} = data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return ""
		}
	}

	// Convert final value to string
	switch v := current.(type) {
	case string:
		return v
	case float64:
		// JSON numbers are float64 - format without trailing zeros
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%g", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		// For complex types, marshal back to JSON
		bytes, _ := json.Marshal(v)
		return string(bytes)
	}
}

// extractMultipartForm extracts a value from multipart form data
func (e *Extractor) extractMultipartForm(r *http.Request, param string) (string, error) {
	// Check content type
	contentType := r.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return "", &ExtractionError{
			Placement: "multipart-form",
			Param:     param,
			Message:   "request is not multipart form data",
		}
	}

	boundary := params["boundary"]
	if boundary == "" {
		return "", &ExtractionError{
			Placement: "multipart-form",
			Param:     param,
			Message:   "no boundary in multipart form",
		}
	}

	// Parse multipart form
	reader := multipart.NewReader(r.Body, boundary)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", &ExtractionError{
				Placement: "multipart-form",
				Param:     param,
				Message:   "failed to parse multipart: " + err.Error(),
			}
		}

		// Check if this is the field we're looking for
		if part.FormName() == param {
			value, err := io.ReadAll(part)
			if err != nil {
				return "", &ExtractionError{
					Placement: "multipart-form",
					Param:     param,
					Message:   "failed to read part: " + err.Error(),
				}
			}
			return string(value), nil
		}
	}

	return "", nil
}

// ExtractionError represents an error during input extraction
type ExtractionError struct {
	Placement string
	Param     string
	Message   string
}

func (e *ExtractionError) Error() string {
	return "extraction error [" + e.Placement + ":" + e.Param + "]: " + e.Message
}
