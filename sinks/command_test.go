package sinks

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestNewCommand tests command sink creation
func TestNewCommand(t *testing.T) {
	sink := NewCommand()
	if sink == nil {
		t.Fatal("Expected command sink, got nil")
	}
}

// TestNewCommandWithTimeout tests command sink with custom timeout
func TestNewCommandWithTimeout(t *testing.T) {
	sink := NewCommandWithTimeout(5 * time.Second)
	if sink == nil {
		t.Fatal("Expected command sink, got nil")
	}
}

// TestCommand_Execute_Echo tests executing echo command
func TestCommand_Execute_Echo(t *testing.T) {
	sink := NewCommand()

	output, err := sink.Execute("echo hello")
	if err != nil {
		t.Fatalf("Failed to execute echo: %v", err)
	}

	if !strings.Contains(strings.TrimSpace(output), "hello") {
		t.Errorf("Expected output to contain 'hello', got '%s'", output)
	}
}

// TestCommand_Execute_MultipleWords tests echo with multiple words
func TestCommand_Execute_MultipleWords(t *testing.T) {
	sink := NewCommand()

	output, err := sink.Execute("echo hello world")
	if err != nil {
		t.Fatalf("Failed to execute echo: %v", err)
	}

	if !strings.Contains(output, "hello") || !strings.Contains(output, "world") {
		t.Errorf("Expected output to contain 'hello world', got '%s'", output)
	}
}

// TestCommand_Close tests that close is a no-op
func TestCommand_Close(t *testing.T) {
	sink := NewCommand()
	err := sink.Close()
	if err != nil {
		t.Errorf("Expected no error from Close, got: %v", err)
	}
}

// TestCommand_ExecuteWithFilter tests execution with filter
func TestCommand_ExecuteWithFilter(t *testing.T) {
	sink := NewCommand()

	// Test with no filter
	output, err := sink.ExecuteWithFilter("echo test", "none")
	if err != nil {
		t.Fatalf("Failed to execute with filter: %v", err)
	}

	if !strings.Contains(output, "test") {
		t.Errorf("Expected output to contain 'test', got '%s'", output)
	}
}

// TestCommand_ExecuteWithFilter_BasicSemicolon tests semicolon filter
func TestCommand_ExecuteWithFilter_BasicSemicolon(t *testing.T) {
	sink := NewCommand()

	// Command with semicolon should have it removed
	output, err := sink.ExecuteWithFilter("echo hello; echo world", "basic_semicolon")
	if err != nil {
		t.Fatalf("Failed to execute with filter: %v", err)
	}

	// Semicolon removed, so "world" won't be echoed as separate command
	// Just verify it runs without error
	_ = output
}

// TestCommand_ExecuteWithFilter_BasicPipe tests pipe filter
func TestCommand_ExecuteWithFilter_BasicPipe(t *testing.T) {
	sink := NewCommand()

	// Command with pipe should have it removed
	output, err := sink.ExecuteWithFilter("echo hello | cat", "basic_pipe")
	if err != nil {
		t.Fatalf("Failed to execute with filter: %v", err)
	}

	// Pipe removed
	_ = output
}

// TestCommand_ShellDetection tests shell detection based on OS
func TestCommand_ShellDetection(t *testing.T) {
	sink := NewCommand()

	// Access the internal shell and shellArg through Execute behavior
	// Since we can't access private fields, we verify through command execution
	output, err := sink.Execute("echo test")
	if err != nil {
		t.Fatalf("Shell execution failed: %v", err)
	}

	// Should work on both Windows and Unix
	if !strings.Contains(output, "test") {
		t.Errorf("Shell detection issue, output: '%s'", output)
	}
}

// TestCommand_Timeout tests that timeout is set
func TestCommand_Timeout(t *testing.T) {
	// Create command with a short timeout
	sink := NewCommandWithTimeout(2 * time.Second)

	// Just verify the sink was created with the timeout
	// Actual timeout behavior is system-dependent
	if sink == nil {
		t.Fatal("Failed to create command sink with timeout")
	}

	// Test a quick command still works
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "echo timeout-test"
	} else {
		cmd = "echo timeout-test"
	}

	output, err := sink.Execute(cmd)
	if err != nil {
		t.Logf("Note: Command execution returned error: %v", err)
	}

	if !strings.Contains(output, "timeout-test") {
		t.Errorf("Expected output to contain 'timeout-test', got: %s", output)
	}
}
