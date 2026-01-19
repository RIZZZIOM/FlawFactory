package sinks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Filesystem provides file operations for path traversal testing
type Filesystem struct {
	basePath string
}

// NewFilesystem creates a new filesystem sink with a temporary directory
func NewFilesystem() (*Filesystem, error) {
	// Create a temporary directory for the lab
	tmpDir, err := os.MkdirTemp("", "flawfactory-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	fs := &Filesystem{basePath: tmpDir}

	// Create default sensitive files
	if err := fs.createDefaultFiles(); err != nil {
		// Clean up on error
		os.RemoveAll(tmpDir)
		return nil, err
	}

	return fs, nil
}

// NewFilesystemWithPath creates a filesystem sink with a specific base path
func NewFilesystemWithPath(basePath string) (*Filesystem, error) {
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	return &Filesystem{basePath: basePath}, nil
}

// Close removes the temporary directory
func (fs *Filesystem) Close() error {
	// Only remove if it's a temp directory (starts with flawfactory-)
	if strings.Contains(fs.basePath, "flawfactory-") {
		return os.RemoveAll(fs.basePath)
	}
	return nil
}

// BasePath returns the base directory
func (fs *Filesystem) BasePath() string {
	return fs.basePath
}

// createDefaultFiles creates default sensitive files for testing
func (fs *Filesystem) createDefaultFiles() error {
	defaultFiles := map[string]string{
		"etc/passwd": `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1000:1000:Admin User:/home/admin:/bin/bash`,

		"etc/shadow": `root:$6$rounds=5000$saltsalt$hashedpassword:18000:0:99999:7:::
daemon:*:18000:0:99999:7:::
admin:$6$rounds=5000$saltsalt$adminhashedpass:18000:0:99999:7:::`,

		"app/config.ini": `[database]
host=localhost
port=5432
username=admin
password=supersecretpassword123
database=production

[api]
key=sk_live_abcdef123456
secret=very_secret_api_key

[debug]
enabled=true
log_level=debug`,

		"app/.env": `DATABASE_URL=postgresql://admin:password123@localhost:5432/app
SECRET_KEY=this_is_a_very_secret_key_12345
API_KEY=api_key_should_not_be_here
DEBUG=true`,

		"var/log/app.log": `[2024-01-15 10:30:45] INFO: Application started
[2024-01-15 10:30:46] DEBUG: Database connection established
[2024-01-15 10:31:00] INFO: User admin logged in from 192.168.1.100
[2024-01-15 10:32:15] ERROR: Failed login attempt for user root from 10.0.0.50
[2024-01-15 10:33:00] DEBUG: SQL Query: SELECT * FROM users WHERE id = 1`,
	}

	for path, content := range defaultFiles {
		if err := fs.WriteFile(path, content); err != nil {
			return err
		}
	}

	return nil
}

// WriteFile creates a file with the given content
func (fs *Filesystem) WriteFile(relativePath, content string) error {
	fullPath := filepath.Join(fs.basePath, relativePath)

	// Create parent directories
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write the file
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", fullPath, err)
	}

	return nil
}

// Read reads a file - intentionally vulnerable to path traversal
func (fs *Filesystem) Read(path string) (string, error) {
	// This is intentionally vulnerable - no path sanitization
	fullPath := filepath.Join(fs.basePath, path)

	content, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("file not found: %s", path)
		}
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	return string(content), nil
}

// ReadWithFilter reads a file with optional filtering
func (fs *Filesystem) ReadWithFilter(path string, filter string) (string, error) {
	// Apply filters based on configuration
	filteredPath := path

	switch filter {
	case "basic_dots":
		// Basic filter that removes ".." sequences
		filteredPath = strings.ReplaceAll(path, "..", "")
	case "basic_slashes":
		// Basic filter that removes path separators
		filteredPath = strings.ReplaceAll(path, "/", "")
		filteredPath = strings.ReplaceAll(filteredPath, "\\", "")
	case "none":
		// No filtering - fully vulnerable
		filteredPath = path
	default:
		filteredPath = path
	}

	return fs.Read(filteredPath)
}

// Exists checks if a file exists
func (fs *Filesystem) Exists(path string) bool {
	fullPath := filepath.Join(fs.basePath, path)
	_, err := os.Stat(fullPath)
	return err == nil
}

// List lists files in a directory
func (fs *Filesystem) List(path string) ([]string, error) {
	fullPath := filepath.Join(fs.basePath, path)

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list directory: %w", err)
	}

	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		files = append(files, name)
	}

	return files, nil
}
