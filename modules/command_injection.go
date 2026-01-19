package modules

import (
	"fmt"
	"net/url"
	"strings"
)

// CommandInjection implements the command_injection vulnerability module
type CommandInjection struct{}

// init registers the module
func init() {
	Register(&CommandInjection{})
}

// Info returns module metadata
func (m *CommandInjection) Info() ModuleInfo {
	return ModuleInfo{
		Name:        "command_injection",
		Description: "OS Command Injection vulnerability for executing arbitrary commands",
		SupportedPlacements: []string{
			"query_param",
			"path_param",
			"form_field",
			"json_field",
			"header",
		},
		RequiresSink: "command",
		ValidVariants: map[string][]string{
			"filter": {"none", "basic_semicolon", "basic_pipe", "basic_both", "url_decode"},
		},
	}
}

// Handle processes the request and executes commands
func (m *CommandInjection) Handle(ctx *HandlerContext) (*Result, error) {
	if ctx.Sinks == nil || ctx.Sinks.Command == nil {
		return nil, fmt.Errorf("Command sink not available")
	}

	// Get configuration
	baseCommand := ctx.GetConfigString("base_command", "")
	filter := ctx.GetConfigString("filter", "none")

	input := ctx.Input

	// Apply filter to input
	input = applyCommandFilter(input, filter)

	// Build the command
	var command string
	if baseCommand != "" {
		// Replace {input} placeholder with user input
		command = strings.ReplaceAll(baseCommand, "{input}", input)
	} else {
		// Direct command execution (very dangerous)
		command = input
	}

	// Execute the command
	output, err := ctx.Sinks.Command.Execute(command)
	if err != nil {
		return &Result{
			Error: err.Error(),
			Data: map[string]interface{}{
				"command": command,
				"output":  output,
				"error":   err.Error(),
			},
		}, nil
	}

	return NewResult(map[string]interface{}{
		"output":  output,
		"command": command,
	}), nil
}

// applyCommandFilter applies command filtering based on configuration
func applyCommandFilter(input, filter string) string {
	switch filter {
	case "none":
		// No filtering - fully vulnerable
		return input
	case "basic_semicolon":
		// Basic filter that removes semicolons (easily bypassed with other operators)
		return strings.ReplaceAll(input, ";", "")
	case "basic_pipe":
		// Basic filter that removes pipes
		return strings.ReplaceAll(input, "|", "")
	case "basic_both":
		// Filter both semicolons and pipes
		input = strings.ReplaceAll(input, ";", "")
		input = strings.ReplaceAll(input, "|", "")
		return input
	case "url_decode":
		// Filter operators first, then URL-decode (bypassable with encoded chars)
		// This simulates a flawed filter that checks before decoding
		input = strings.ReplaceAll(input, ";", "")
		input = strings.ReplaceAll(input, "|", "")
		input = strings.ReplaceAll(input, "&", "")
		input = strings.ReplaceAll(input, "`", "")
		input = strings.ReplaceAll(input, "$", "")
		// URL decode after filtering - allows %26 → & bypass
		decoded, err := url.QueryUnescape(input)
		if err != nil {
			return input
		}
		return decoded
	default:
		return input
	}
}
