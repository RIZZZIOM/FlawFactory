package sinks

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Command provides command execution for command injection testing
type Command struct {
	timeout  time.Duration
	shell    string
	shellArg string
}

// NewCommand creates a new command sink with default settings
func NewCommand() *Command {
	shell := "/bin/sh"
	shellArg := "-c"

	if runtime.GOOS == "windows" {
		shell = "cmd.exe"
		shellArg = "/C"
	}

	return &Command{
		timeout:  30 * time.Second,
		shell:    shell,
		shellArg: shellArg,
	}
}

// NewCommandWithTimeout creates a command sink with a custom timeout
func NewCommandWithTimeout(timeout time.Duration) *Command {
	cmd := NewCommand()
	cmd.timeout = timeout
	return cmd
}

// Close is a no-op for the command sink
func (c *Command) Close() error {
	return nil
}

// Execute runs a command through the shell - intentionally vulnerable
func (c *Command) Execute(command string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	// Execute through shell - this is intentionally vulnerable to injection
	cmd := exec.CommandContext(ctx, c.shell, c.shellArg, command)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	// Combine stdout and stderr
	output := stdout.String()
	if stderr.Len() > 0 {
		if output != "" {
			output += "\n"
		}
		output += stderr.String()
	}

	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("command timed out after %v", c.timeout)
	}

	if err != nil {
		// Include the error but still return output
		return output, fmt.Errorf("command failed: %w\nOutput: %s", err, output)
	}

	return strings.TrimSpace(output), nil
}

// ExecuteWithFilter runs a command with optional filtering
func (c *Command) ExecuteWithFilter(command string, filter string) (string, error) {
	filteredCommand := command

	switch filter {
	case "basic_semicolon":
		// Basic filter that removes semicolons
		filteredCommand = strings.ReplaceAll(command, ";", "")
	case "basic_pipe":
		// Basic filter that removes pipes
		filteredCommand = strings.ReplaceAll(command, "|", "")
	case "basic_both":
		// Filter both semicolons and pipes
		filteredCommand = strings.ReplaceAll(command, ";", "")
		filteredCommand = strings.ReplaceAll(filteredCommand, "|", "")
	case "none":
		// No filtering - fully vulnerable
		filteredCommand = command
	default:
		filteredCommand = command
	}

	return c.Execute(filteredCommand)
}

// ExecuteWithBase prepends a base command - common pattern for command injection
func (c *Command) ExecuteWithBase(baseCommand, userInput string) (string, error) {
	// Replace {input} placeholder with user input
	fullCommand := strings.ReplaceAll(baseCommand, "{input}", userInput)
	return c.Execute(fullCommand)
}

// SetTimeout updates the command timeout
func (c *Command) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}
