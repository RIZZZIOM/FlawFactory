package sinks

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNewFilesystem tests filesystem sink creation
func TestNewFilesystem(t *testing.T) {
	sink, err := NewFilesystem()
	if err != nil {
		t.Fatalf("Failed to create filesystem sink: %v", err)
	}
	defer sink.Close()

	if sink == nil {
		t.Fatal("Expected filesystem sink, got nil")
	}
}

// TestFilesystem_BasePath tests that base directory is created
func TestFilesystem_BasePath(t *testing.T) {
	sink, err := NewFilesystem()
	if err != nil {
		t.Fatalf("Failed to create filesystem sink: %v", err)
	}
	defer sink.Close()

	basePath := sink.BasePath()
	if basePath == "" {
		t.Fatal("Expected non-empty base path")
	}

	// Check directory exists
	info, err := os.Stat(basePath)
	if err != nil {
		t.Fatalf("Base directory does not exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("Base path is not a directory")
	}
}

// TestFilesystem_WriteFile tests writing a file
func TestFilesystem_WriteFile(t *testing.T) {
	sink, err := NewFilesystem()
	if err != nil {
		t.Fatalf("Failed to create filesystem sink: %v", err)
	}
	defer sink.Close()

	content := "Hello, World!"
	err = sink.WriteFile("test.txt", content)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	// Verify file exists and has correct content
	path := filepath.Join(sink.BasePath(), "test.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read written file: %v", err)
	}
	if string(data) != content {
		t.Errorf("Expected content '%s', got '%s'", content, string(data))
	}
}

// TestFilesystem_WriteFile_Nested tests writing a file in nested directory
func TestFilesystem_WriteFile_Nested(t *testing.T) {
	sink, err := NewFilesystem()
	if err != nil {
		t.Fatalf("Failed to create filesystem sink: %v", err)
	}
	defer sink.Close()

	content := "Nested content"
	err = sink.WriteFile("subdir/nested/file.txt", content)
	if err != nil {
		t.Fatalf("Failed to write nested file: %v", err)
	}

	// Verify
	path := filepath.Join(sink.BasePath(), "subdir", "nested", "file.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read nested file: %v", err)
	}
	if string(data) != content {
		t.Errorf("Expected content '%s', got '%s'", content, string(data))
	}
}

// TestFilesystem_Read tests reading a file
func TestFilesystem_Read(t *testing.T) {
	sink, err := NewFilesystem()
	if err != nil {
		t.Fatalf("Failed to create filesystem sink: %v", err)
	}
	defer sink.Close()

	// Write first
	content := "Read test content"
	err = sink.WriteFile("read_test.txt", content)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	// Read back using the Read method (vulnerable path traversal)
	data, err := sink.Read("read_test.txt")
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if data != content {
		t.Errorf("Expected '%s', got '%s'", content, data)
	}
}

// TestFilesystem_Read_NotExists tests reading non-existent file
func TestFilesystem_Read_NotExists(t *testing.T) {
	sink, err := NewFilesystem()
	if err != nil {
		t.Fatalf("Failed to create filesystem sink: %v", err)
	}
	defer sink.Close()

	_, err = sink.Read("nonexistent.txt")
	if err == nil {
		t.Error("Expected error when reading non-existent file")
	}
}

// TestFilesystem_DefaultFiles tests that default sensitive files are created
func TestFilesystem_DefaultFiles(t *testing.T) {
	sink, err := NewFilesystem()
	if err != nil {
		t.Fatalf("Failed to create filesystem sink: %v", err)
	}
	defer sink.Close()

	// Check for default files using Read
	defaultFiles := []string{
		"etc/passwd",
		"etc/shadow",
		"app/config.ini",
		"app/.env",
	}

	for _, file := range defaultFiles {
		_, err := sink.Read(file)
		if err != nil {
			t.Errorf("Expected default file '%s' to exist: %v", file, err)
		}
	}
}

// TestFilesystem_Close tests cleanup
func TestFilesystem_Close(t *testing.T) {
	sink, err := NewFilesystem()
	if err != nil {
		t.Fatalf("Failed to create filesystem sink: %v", err)
	}

	basePath := sink.BasePath()

	// Verify directory exists
	if _, err := os.Stat(basePath); err != nil {
		t.Fatalf("Base directory should exist: %v", err)
	}

	// Close (cleanup)
	err = sink.Close()
	if err != nil {
		t.Fatalf("Failed to close: %v", err)
	}

	// Verify directory no longer exists
	if _, err := os.Stat(basePath); !os.IsNotExist(err) {
		t.Error("Base directory should not exist after close")
	}
}

// TestNewFilesystemWithPath tests creating with specific path
func TestNewFilesystemWithPath(t *testing.T) {
	// Create a temp directory for testing
	tmpDir, err := os.MkdirTemp("", "fs-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sink, err := NewFilesystemWithPath(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create filesystem with path: %v", err)
	}

	if sink.BasePath() != tmpDir {
		t.Errorf("Expected base path '%s', got '%s'", tmpDir, sink.BasePath())
	}
}

// TestFilesystem_ReadWithFilter tests reading with filter
func TestFilesystem_ReadWithFilter(t *testing.T) {
	sink, err := NewFilesystem()
	if err != nil {
		t.Fatalf("Failed to create filesystem sink: %v", err)
	}
	defer sink.Close()

	// Write a file
	err = sink.WriteFile("filter_test.txt", "filter content")
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	// Read with no filter
	data, err := sink.ReadWithFilter("filter_test.txt", "none")
	if err != nil {
		t.Fatalf("Failed to read with filter: %v", err)
	}
	if data != "filter content" {
		t.Errorf("Expected 'filter content', got '%s'", data)
	}
}
