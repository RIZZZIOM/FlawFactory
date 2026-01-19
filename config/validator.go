package config

import (
	"fmt"
	"strings"

	"github.com/RIZZZIOM/FlawFactory/modules"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors is a collection of validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("configuration validation failed with %d error(s):\n", len(e)))
	for i, err := range e {
		sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, err.Error()))
	}
	return sb.String()
}

// ValidationWarning represents a non-fatal configuration issue
type ValidationWarning struct {
	Field        string
	Message      string
	DefaultValue string
}

func (w ValidationWarning) String() string {
	if w.DefaultValue != "" {
		return fmt.Sprintf("%s: %s (using default: %s)", w.Field, w.Message, w.DefaultValue)
	}
	return fmt.Sprintf("%s: %s", w.Field, w.Message)
}

// ValidationWarnings is a collection of validation warnings
type ValidationWarnings []ValidationWarning

// ValidationResult contains both errors and warnings from validation
type ValidationResult struct {
	Errors   ValidationErrors
	Warnings ValidationWarnings
}

// HasErrors returns true if there are validation errors
func (r *ValidationResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// HasWarnings returns true if there are validation warnings
func (r *ValidationResult) HasWarnings() bool {
	return len(r.Warnings) > 0
}

// Validate validates the entire configuration (returns only errors for backward compatibility)
func Validate(cfg *Config) error {
	result := ValidateWithWarnings(cfg)
	if result.HasErrors() {
		return result.Errors
	}
	return nil
}

// ValidateWithWarnings validates the entire configuration and returns both errors and warnings
func ValidateWithWarnings(cfg *Config) *ValidationResult {
	result := &ValidationResult{}

	// Validate app section
	result.Errors = append(result.Errors, validateApp(&cfg.App)...)

	// Validate endpoints
	endpointErrs, endpointWarns := validateEndpointsWithWarnings(cfg.Endpoints)
	result.Errors = append(result.Errors, endpointErrs...)
	result.Warnings = append(result.Warnings, endpointWarns...)

	// Validate data section
	if cfg.Data != nil {
		result.Errors = append(result.Errors, validateData(cfg.Data)...)
	}

	// Validate files section
	result.Errors = append(result.Errors, validateFiles(cfg.Files)...)

	return result
}

// validateApp validates the app configuration section
func validateApp(app *AppConfig) ValidationErrors {
	var errs ValidationErrors

	// Validate name
	if app.Name == "" {
		errs = append(errs, ValidationError{
			Field:   "app.name",
			Message: "name is required and cannot be empty",
		})
	}

	// Validate port
	if app.Port < 1 || app.Port > 65535 {
		errs = append(errs, ValidationError{
			Field:   "app.port",
			Message: fmt.Sprintf("port must be between 1 and 65535, got %d", app.Port),
		})
	}

	return errs
}

// validateEndpoints validates all endpoints
func validateEndpoints(endpoints []EndpointConfig) ValidationErrors {
	var errs ValidationErrors

	if len(endpoints) == 0 {
		errs = append(errs, ValidationError{
			Field:   "endpoints",
			Message: "at least one endpoint is required",
		})
		return errs
	}

	// Track unique paths for duplicate detection
	pathMap := make(map[string]int)

	validMethods := map[string]bool{
		"GET":    true,
		"POST":   true,
		"PUT":    true,
		"DELETE": true,
		"PATCH":  true,
	}

	validResponseTypes := map[string]bool{
		"json": true,
		"html": true,
		"xml":  true,
		"text": true,
	}

	for i, endpoint := range endpoints {
		prefix := fmt.Sprintf("endpoints[%d]", i)

		// Validate path
		if endpoint.Path == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.path", prefix),
				Message: "path is required",
			})
		} else if !strings.HasPrefix(endpoint.Path, "/") {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.path", prefix),
				Message: fmt.Sprintf("path must start with '/', got '%s'", endpoint.Path),
			})
		}

		// Validate method
		if endpoint.Method == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.method", prefix),
				Message: "method is required",
			})
		} else if !validMethods[strings.ToUpper(endpoint.Method)] {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.method", prefix),
				Message: fmt.Sprintf("invalid HTTP method '%s', must be one of: GET, POST, PUT, DELETE, PATCH", endpoint.Method),
			})
		}

		// Validate response_type
		if endpoint.ResponseType != "" && !validResponseTypes[endpoint.ResponseType] {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.response_type", prefix),
				Message: fmt.Sprintf("invalid response type '%s', must be one of: json, html, xml, text", endpoint.ResponseType),
			})
		}

		// Check for duplicate path+method combinations
		key := fmt.Sprintf("%s:%s", strings.ToUpper(endpoint.Method), endpoint.Path)
		if prevIndex, exists := pathMap[key]; exists {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.path", prefix),
				Message: fmt.Sprintf("duplicate endpoint '%s %s' (previously defined at index %d)", endpoint.Method, endpoint.Path, prevIndex),
			})
		} else {
			pathMap[key] = i
		}

		// Validate vulnerabilities
		errs = append(errs, validateVulnerabilities(endpoint.Vulnerabilities, prefix)...)
	}

	return errs
}

// validateEndpointsWithWarnings validates all endpoints and returns both errors and warnings
func validateEndpointsWithWarnings(endpoints []EndpointConfig) (ValidationErrors, ValidationWarnings) {
	var errs ValidationErrors
	var warns ValidationWarnings

	if len(endpoints) == 0 {
		errs = append(errs, ValidationError{
			Field:   "endpoints",
			Message: "at least one endpoint is required",
		})
		return errs, warns
	}

	// Track unique paths for duplicate detection
	pathMap := make(map[string]int)

	validMethods := map[string]bool{
		"GET":    true,
		"POST":   true,
		"PUT":    true,
		"DELETE": true,
		"PATCH":  true,
	}

	validResponseTypes := map[string]bool{
		"json": true,
		"html": true,
		"xml":  true,
		"text": true,
	}

	for i, endpoint := range endpoints {
		prefix := fmt.Sprintf("endpoints[%d]", i)

		// Validate path
		if endpoint.Path == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.path", prefix),
				Message: "path is required",
			})
		} else if !strings.HasPrefix(endpoint.Path, "/") {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.path", prefix),
				Message: fmt.Sprintf("path must start with '/', got '%s'", endpoint.Path),
			})
		}

		// Validate method
		if endpoint.Method == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.method", prefix),
				Message: "method is required",
			})
		} else if !validMethods[strings.ToUpper(endpoint.Method)] {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.method", prefix),
				Message: fmt.Sprintf("invalid HTTP method '%s', must be one of: GET, POST, PUT, DELETE, PATCH", endpoint.Method),
			})
		}

		// Validate response_type
		if endpoint.ResponseType != "" && !validResponseTypes[endpoint.ResponseType] {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.response_type", prefix),
				Message: fmt.Sprintf("invalid response type '%s', must be one of: json, html, xml, text", endpoint.ResponseType),
			})
		}

		// Check for duplicate path+method combinations
		key := fmt.Sprintf("%s:%s", strings.ToUpper(endpoint.Method), endpoint.Path)
		if prevIndex, exists := pathMap[key]; exists {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.path", prefix),
				Message: fmt.Sprintf("duplicate endpoint '%s %s' (previously defined at index %d)", endpoint.Method, endpoint.Path, prevIndex),
			})
		} else {
			pathMap[key] = i
		}

		// Validate vulnerabilities with warnings
		vulnErrs, vulnWarns := validateVulnerabilitiesWithWarnings(endpoint.Vulnerabilities, prefix, endpoint.Path)
		errs = append(errs, vulnErrs...)
		warns = append(warns, vulnWarns...)
	}

	return errs, warns
}

// validateVulnerabilities validates vulnerability configurations
func validateVulnerabilities(vulns []VulnerabilityConfig, endpointPrefix string) ValidationErrors {
	var errs ValidationErrors

	// Track unique params within this endpoint
	paramMap := make(map[string]int)

	validPlacements := map[string]bool{
		"query_param":    true,
		"path_param":     true,
		"form_field":     true,
		"json_field":     true,
		"header":         true,
		"cookie":         true,
		"multipart-form": true,
	}

	for i, vuln := range vulns {
		prefix := fmt.Sprintf("%s.vulnerabilities[%d]", endpointPrefix, i)

		// Validate type
		if vuln.Type == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.type", prefix),
				Message: "vulnerability type is required",
			})
		}
		// Note: We can't validate if the type exists in the registry yet
		// since the registry isn't implemented. That will happen in Phase 5.

		// Validate placement
		if vuln.Placement == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.placement", prefix),
				Message: "placement is required",
			})
		} else if !validPlacements[vuln.Placement] {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.placement", prefix),
				Message: fmt.Sprintf("invalid placement '%s', must be one of: query_param, path_param, form_field, json_field, header, cookie, multipart-form", vuln.Placement),
			})
		}

		// Validate param
		if vuln.Param == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.param", prefix),
				Message: "param is required",
			})
		} else {
			// Check for duplicate params
			if prevIndex, exists := paramMap[vuln.Param]; exists {
				errs = append(errs, ValidationError{
					Field:   fmt.Sprintf("%s.param", prefix),
					Message: fmt.Sprintf("duplicate param '%s' (previously used at vulnerability index %d)", vuln.Param, prevIndex),
				})
			} else {
				paramMap[vuln.Param] = i
			}
		}
	}

	return errs
}

// validateVulnerabilitiesWithWarnings validates vulnerability configurations and checks module-specific config
func validateVulnerabilitiesWithWarnings(vulns []VulnerabilityConfig, endpointPrefix string, endpointPath string) (ValidationErrors, ValidationWarnings) {
	var errs ValidationErrors
	var warns ValidationWarnings

	// Track unique params within this endpoint
	paramMap := make(map[string]int)

	validPlacements := map[string]bool{
		"query_param":    true,
		"path_param":     true,
		"form_field":     true,
		"json_field":     true,
		"header":         true,
		"cookie":         true,
		"multipart-form": true,
	}

	for i, vuln := range vulns {
		prefix := fmt.Sprintf("%s.vulnerabilities[%d]", endpointPrefix, i)

		// Validate type
		if vuln.Type == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.type", prefix),
				Message: "vulnerability type is required",
			})
		}

		// Validate placement
		if vuln.Placement == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.placement", prefix),
				Message: "placement is required",
			})
		} else if !validPlacements[vuln.Placement] {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.placement", prefix),
				Message: fmt.Sprintf("invalid placement '%s', must be one of: query_param, path_param, form_field, json_field, header, cookie, multipart-form", vuln.Placement),
			})
		}

		// Validate param
		if vuln.Param == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.param", prefix),
				Message: "param is required",
			})
		} else {
			// Check for duplicate params
			if prevIndex, exists := paramMap[vuln.Param]; exists {
				errs = append(errs, ValidationError{
					Field:   fmt.Sprintf("%s.param", prefix),
					Message: fmt.Sprintf("duplicate param '%s' (previously used at vulnerability index %d)", vuln.Param, prevIndex),
				})
			} else {
				paramMap[vuln.Param] = i
			}
		}

		// Validate module-specific config values (generates warnings, not errors)
		if vuln.Type != "" && vuln.Config != nil {
			for configKey, configValue := range vuln.Config {
				// Convert value to string for validation
				valueStr := fmt.Sprintf("%v", configValue)
				isValid, validOptions, defaultVal := modules.ValidateConfigValue(vuln.Type, configKey, valueStr)
				if !isValid && len(validOptions) > 0 {
					warns = append(warns, ValidationWarning{
						Field:        fmt.Sprintf("%s.config.%s", prefix, configKey),
						Message:      fmt.Sprintf("invalid value '%s' for %s at %s, valid options: %v", valueStr, configKey, endpointPath, validOptions),
						DefaultValue: defaultVal,
					})
				}
			}
		}
	}

	return errs, warns
}

// validateData validates the data section (database tables)
func validateData(data *DataConfig) ValidationErrors {
	var errs ValidationErrors

	if len(data.Tables) == 0 {
		// Having a data section with no tables is unusual but not an error
		return errs
	}

	for tableName, table := range data.Tables {
		prefix := fmt.Sprintf("data.tables.%s", tableName)

		// Validate table name
		if tableName == "" {
			errs = append(errs, ValidationError{
				Field:   "data.tables",
				Message: "table name cannot be empty",
			})
			continue
		}

		// Validate columns
		if len(table.Columns) == 0 {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.columns", prefix),
				Message: "at least one column is required",
			})
		}

		// Validate rows
		for i, row := range table.Rows {
			if len(row) != len(table.Columns) {
				errs = append(errs, ValidationError{
					Field:   fmt.Sprintf("%s.rows[%d]", prefix, i),
					Message: fmt.Sprintf("row has %d values but table has %d columns", len(row), len(table.Columns)),
				})
			}
		}
	}

	return errs
}

// validateFiles validates the files section
func validateFiles(files []FileConfig) ValidationErrors {
	var errs ValidationErrors

	// Track unique file paths
	pathMap := make(map[string]int)

	for i, file := range files {
		prefix := fmt.Sprintf("files[%d]", i)

		// Validate path
		if file.Path == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s.path", prefix),
				Message: "file path is required",
			})
		} else {
			// Check for duplicate paths
			if prevIndex, exists := pathMap[file.Path]; exists {
				errs = append(errs, ValidationError{
					Field:   fmt.Sprintf("%s.path", prefix),
					Message: fmt.Sprintf("duplicate file path '%s' (previously defined at index %d)", file.Path, prevIndex),
				})
			} else {
				pathMap[file.Path] = i
			}
		}

		// Content can be empty (empty files are valid)
	}

	return errs
}
