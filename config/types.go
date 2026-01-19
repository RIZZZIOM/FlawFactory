package config

// Config represents the entire YAML configuration file
type Config struct {
	App       AppConfig        `yaml:"app"`
	Data      *DataConfig      `yaml:"data,omitempty"`
	Files     []FileConfig     `yaml:"files,omitempty"`
	Endpoints []EndpointConfig `yaml:"endpoints"`
}

// AppConfig holds application-level settings
type AppConfig struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description,omitempty"`
	Port        int        `yaml:"port"`
	Host        string     `yaml:"host,omitempty"` // Host to bind to (default: 0.0.0.0)
	TLS         *TLSConfig `yaml:"tls,omitempty"`
}

// TLSConfig holds HTTPS/TLS configuration
type TLSConfig struct {
	Enabled      bool   `yaml:"enabled"`
	CertFile     string `yaml:"cert_file,omitempty"`
	KeyFile      string `yaml:"key_file,omitempty"`
	AutoGenerate bool   `yaml:"auto_generate,omitempty"`
}

// DataConfig holds database table definitions
type DataConfig struct {
	Tables map[string]TableConfig `yaml:"tables,omitempty"`
}

// TableConfig defines a database table structure
type TableConfig struct {
	Columns []string        `yaml:"columns"`
	Rows    [][]interface{} `yaml:"rows"`
}

// FileConfig defines a file to be created
type FileConfig struct {
	Path    string `yaml:"path"`
	Content string `yaml:"content"`
}

// EndpointConfig defines an HTTP endpoint
type EndpointConfig struct {
	Path            string                `yaml:"path"`
	Method          string                `yaml:"method"`
	ResponseType    string                `yaml:"response_type,omitempty"`
	Vulnerabilities []VulnerabilityConfig `yaml:"vulnerabilities"`
}

// VulnerabilityConfig defines a vulnerability on an endpoint
type VulnerabilityConfig struct {
	Type      string                 `yaml:"type"`
	Placement string                 `yaml:"placement"`
	Param     string                 `yaml:"param"`
	Config    map[string]interface{} `yaml:"config,omitempty"`
}
