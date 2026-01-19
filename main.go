package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/RIZZZIOM/FlawFactory/builder"
	"github.com/RIZZZIOM/FlawFactory/config"
	"github.com/RIZZZIOM/FlawFactory/modules"
)

// ANSI color codes for terminal output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "run":
		runCommand()
	case "validate":
		validateCommand()
	case "modules":
		modulesCommand()
	default:
		fmt.Printf("Unknown command: %s\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func runCommand() {
	runFlags := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := runFlags.String("config", "", "Path to YAML config file (required)")
	configShort := runFlags.String("c", "", "Path to YAML config file (shorthand)")
	port := runFlags.Int("port", 0, "Override port from config")
	portShort := runFlags.Int("p", 0, "Override port from config (shorthand)")

	runFlags.Parse(os.Args[2:])

	configFile := *configPath
	if configFile == "" {
		configFile = *configShort
	}

	portOverride := *port
	if portOverride == 0 {
		portOverride = *portShort
	}

	if configFile == "" {
		fmt.Printf("\n  %s✗ Error:%s -config flag is required\n\n", colorRed, colorReset)
		runFlags.PrintDefaults()
		os.Exit(1)
	}

	// Print startup banner
	printBanner()

	// Load configuration
	cfg, err := config.Load(configFile)
	if err != nil {
		printConfigError(configFile, err)
		os.Exit(1)
	}

	// Override port if specified
	if portOverride > 0 {
		cfg.App.Port = portOverride
	}

	// Derive log file path from config file name
	// e.g., ssrf.yaml -> log/ssrf.json
	configBaseName := filepath.Base(configFile)
	configNameWithoutExt := strings.TrimSuffix(configBaseName, filepath.Ext(configBaseName))
	logFilePath := filepath.Join("log", configNameWithoutExt+".json")

	// Build the server with JSON logging
	b := builder.New(cfg, logFilePath)
	srv, err := b.Build()
	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}

	// Print configuration summary
	printConfigSummary(cfg)

	// Start server in a goroutine
	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Graceful shutdown with 5 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Stop(ctx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}

	// Clean up builder resources
	if err := b.Close(); err != nil {
		log.Printf("Warning: cleanup error: %v", err)
	}
}

func validateCommand() {
	validateFlags := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := validateFlags.String("config", "", "Path to YAML config file (required)")
	configShort := validateFlags.String("c", "", "Path to YAML config file (shorthand)")

	validateFlags.Parse(os.Args[2:])

	configFile := *configPath
	if configFile == "" {
		configFile = *configShort
	}

	if configFile == "" {
		fmt.Printf("\n  %s✗ Error:%s -config flag is required\n\n", colorRed, colorReset)
		validateFlags.PrintDefaults()
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load(configFile)
	if err != nil {
		printConfigError(configFile, err)
		os.Exit(1)
	}

	// Validate with warnings
	result := config.ValidateWithWarnings(cfg)
	if result.HasErrors() {
		printConfigError(configFile, result.Errors)
		os.Exit(1)
	}

	// Print success header
	fmt.Println()
	fmt.Printf("  %s✓ Configuration Valid%s\n", colorGreen+colorBold, colorReset)
	fmt.Println(colorDim + "  ─────────────────────────────────────────" + colorReset)

	// Print warnings if any
	if result.HasWarnings() {
		fmt.Println()
		fmt.Printf("  %s⚠ WARNINGS%s\n", colorYellow+colorBold, colorReset)
		for _, warn := range result.Warnings {
			fmt.Printf("    %s•%s %s\n", colorYellow, colorReset, warn.Field)
			fmt.Printf("      %s%s%s\n", colorDim, warn.Message, colorReset)
			if warn.DefaultValue != "" {
				fmt.Printf("      %s→ proceeding with default: %s%s%s\n", colorDim, colorCyan, warn.DefaultValue, colorReset)
			}
		}
	}

	fmt.Println()

	// Summary
	fmt.Println(colorYellow + "  SUMMARY" + colorReset)
	fmt.Printf("    %sApp Name:%s    %s\n", colorDim, colorReset, cfg.App.Name)
	if cfg.App.Description != "" {
		fmt.Printf("    %sDescription:%s %s\n", colorDim, colorReset, cfg.App.Description)
	}
	fmt.Printf("    %sPort:%s        %s%d%s\n", colorDim, colorReset, colorCyan, cfg.App.Port, colorReset)
	fmt.Printf("    %sEndpoints:%s   %s%d%s\n", colorDim, colorReset, colorCyan, len(cfg.Endpoints), colorReset)

	if cfg.Data != nil && len(cfg.Data.Tables) > 0 {
		fmt.Printf("    %sTables:%s      %s%d%s\n", colorDim, colorReset, colorCyan, len(cfg.Data.Tables), colorReset)
	}

	if len(cfg.Files) > 0 {
		fmt.Printf("    %sFiles:%s       %s%d%s\n", colorDim, colorReset, colorCyan, len(cfg.Files), colorReset)
	}

	// Count total vulnerabilities
	totalVulns := 0
	for _, endpoint := range cfg.Endpoints {
		totalVulns += len(endpoint.Vulnerabilities)
	}
	if totalVulns > 0 {
		fmt.Printf("    %sVulnerabilities:%s %s%d%s\n", colorDim, colorReset, colorRed, totalVulns, colorReset)
	}

	fmt.Println()
}

func modulesCommand() {
	fmt.Println()
	fmt.Println(colorCyan + colorBold + "┌─────────────────────────────────────────┐" + colorReset)
	fmt.Println(colorCyan + colorBold + "│       AVAILABLE VULNERABILITY MODULES   │" + colorReset)
	fmt.Println(colorCyan + colorBold + "└─────────────────────────────────────────┘" + colorReset)
	fmt.Println()

	moduleList := modules.List()
	if len(moduleList) == 0 {
		fmt.Printf("  %s⚠ No modules registered%s\n", colorYellow, colorReset)
		fmt.Println()
		return
	}

	for _, info := range moduleList {
		fmt.Printf("  %s•%s %s%s%s\n", colorGreen, colorReset, colorGreen+colorBold, info.Name, colorReset)
		fmt.Printf("     %sDescription:%s %s\n", colorDim, colorReset, info.Description)
		fmt.Printf("     %sPlacements:%s  %s%v%s\n", colorDim, colorReset, colorCyan, info.SupportedPlacements, colorReset)
		if info.RequiresSink != "" {
			fmt.Printf("     %sRequires:%s    %s%s sink%s\n", colorDim, colorReset, colorYellow, info.RequiresSink, colorReset)
		}
		fmt.Println()
	}
}

func printBanner() {
	banner := colorPurple + `
    ███████╗██╗      █████╗ ██╗    ██╗███████╗ █████╗  ██████╗████████╗ ██████╗ ██████╗ ██╗   ██╗
    ██╔════╝██║     ██╔══██╗██║    ██║██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗╚██╗ ██╔╝
    █████╗  ██║     ███████║██║ █╗ ██║█████╗  ███████║██║        ██║   ██║   ██║██████╔╝ ╚████╔╝ 
    ██╔══╝  ██║     ██╔══██║██║███╗██║██╔══╝  ██╔══██║██║        ██║   ██║   ██║██╔══██╗  ╚██╔╝  
    ██║     ███████╗██║  ██║╚███╔███╔╝██║     ██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║   ██║   
    ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
` + colorReset

	tagline := colorDim + "    ─────────────────────────────────────────────────────────────────────────────────────────" + colorReset
	subtitle := colorCyan + colorBold + "                        Config-driven vulnerable web application generator" + colorReset
	version := colorDim + "                                          Version 1.0" + colorReset

	fmt.Println(banner)
	fmt.Println(tagline)
	fmt.Println(subtitle)
	fmt.Println(version)
	fmt.Println()
}

func printConfigSummary(cfg *config.Config) {
	fmt.Println(colorCyan + colorBold + "┌─────────────────────────────────────────┐" + colorReset)
	fmt.Println(colorCyan + colorBold + "│         CONFIGURATION SUMMARY           │" + colorReset)
	fmt.Println(colorCyan + colorBold + "└─────────────────────────────────────────┘" + colorReset)
	fmt.Println()

	// App info section
	fmt.Println(colorYellow + "  ◆ APPLICATION" + colorReset)
	fmt.Printf("    %sName:%s        %s\n", colorDim, colorReset, cfg.App.Name)
	if cfg.App.Description != "" {
		fmt.Printf("    %sDescription:%s %s\n", colorDim, colorReset, cfg.App.Description)
	}
	host := cfg.App.Host
	if host == "" {
		host = "127.0.0.1"
	}
	fmt.Printf("    %sHost:%s        %s%s%s\n", colorDim, colorReset, colorGreen, host, colorReset)
	fmt.Printf("    %sPort:%s        %s%d%s\n", colorDim, colorReset, colorGreen, cfg.App.Port, colorReset)
	fmt.Println()

	// Resources section
	fmt.Println(colorYellow + "  ◆ RESOURCES" + colorReset)
	fmt.Printf("    %sEndpoints:%s   %s%d%s\n", colorDim, colorReset, colorCyan, len(cfg.Endpoints), colorReset)

	if cfg.Data != nil && len(cfg.Data.Tables) > 0 {
		fmt.Printf("    %sTables:%s      %s%d%s\n", colorDim, colorReset, colorCyan, len(cfg.Data.Tables), colorReset)
	}

	if len(cfg.Files) > 0 {
		fmt.Printf("    %sFiles:%s       %s%d%s\n", colorDim, colorReset, colorCyan, len(cfg.Files), colorReset)
	}
	fmt.Println()

	// Count vulnerabilities by type
	vulnCount := make(map[string]int)
	for _, endpoint := range cfg.Endpoints {
		for _, vuln := range endpoint.Vulnerabilities {
			vulnCount[vuln.Type]++
		}
	}

	if len(vulnCount) > 0 {
		fmt.Println(colorYellow + "  ◆ VULNERABILITIES" + colorReset)
		for vulnType, count := range vulnCount {
			icon := getVulnIcon(vulnType)
			fmt.Printf("    %s %s%-20s%s %s%d%s\n", icon, colorDim, vulnType, colorReset, colorRed, count, colorReset)
		}
		fmt.Println()
	}

	fmt.Println(colorDim + "  ─────────────────────────────────────────" + colorReset)
	fmt.Printf("  %s✓ Server ready at:%s %shttp://%s:%d%s\n", colorGreen, colorReset, colorBold, host, cfg.App.Port, colorReset)
	fmt.Println(colorDim + "  ─────────────────────────────────────────" + colorReset)
	fmt.Println()
}

func getVulnIcon(vulnType string) string {
	return "•"
}

func printUsage() {
	// Mini banner for help
	fmt.Println()
	fmt.Println(colorPurple + colorBold + "  FlawFactory" + colorReset + colorDim + " - Config-driven vulnerable web application generator" + colorReset)
	fmt.Println()

	// Usage section
	fmt.Println(colorYellow + "  USAGE" + colorReset)
	fmt.Printf("    %s$%s flawfactory %s<command>%s [flags]\n", colorDim, colorReset, colorCyan, colorReset)
	fmt.Println()

	// Commands section
	fmt.Println(colorYellow + "  COMMANDS" + colorReset)
	fmt.Printf("    %srun%s        %sStart the vulnerable web server%s\n", colorGreen, colorReset, colorDim, colorReset)
	fmt.Printf("    %svalidate%s   %sValidate config file without starting%s\n", colorGreen, colorReset, colorDim, colorReset)
	fmt.Printf("    %smodules%s    %sList available vulnerability modules%s\n", colorGreen, colorReset, colorDim, colorReset)
	fmt.Println()

	// Examples section
	fmt.Println(colorYellow + "  EXAMPLES" + colorReset)
	fmt.Printf("    %s# Start server with config%s\n", colorDim, colorReset)
	fmt.Printf("    $ flawfactory %srun%s -c %sconfig.yaml%s\n", colorGreen, colorReset, colorCyan, colorReset)
	fmt.Println()
	fmt.Printf("    %s# Start on custom port%s\n", colorDim, colorReset)
	fmt.Printf("    $ flawfactory %srun%s -c %sconfig.yaml%s -p %s9090%s\n", colorGreen, colorReset, colorCyan, colorReset, colorCyan, colorReset)
	fmt.Println()
	fmt.Printf("    %s# Validate configuration%s\n", colorDim, colorReset)
	fmt.Printf("    $ flawfactory %svalidate%s -c %sconfig.yaml%s\n", colorGreen, colorReset, colorCyan, colorReset)
	fmt.Println()

	// Flags section
	fmt.Println(colorYellow + "  FLAGS" + colorReset)
	fmt.Printf("    %s-c, --config%s  %spath%s   %sPath to YAML configuration file%s\n", colorGreen, colorReset, colorCyan, colorReset, colorDim, colorReset)
	fmt.Printf("    %s-p, --port%s    %sint%s    %sOverride port from config%s\n", colorGreen, colorReset, colorCyan, colorReset, colorDim, colorReset)
	fmt.Printf("    %s-h, --help%s            %sShow help for a command%s\n", colorGreen, colorReset, colorDim, colorReset)
	fmt.Println()

	// Footer
	fmt.Printf("  %sRun '%sflawfactory <command> -h%s' for more information on a command%s\n", colorDim, colorReset, colorDim, colorReset)
	fmt.Println()
}

// printConfigError displays a nicely formatted configuration error
func printConfigError(configFile string, err error) {
	fmt.Println()
	fmt.Printf("  %s✗ Configuration Error%s\n", colorRed+colorBold, colorReset)
	fmt.Println(colorDim + "  ─────────────────────────────────────────" + colorReset)
	fmt.Printf("  %sFile:%s %s\n", colorDim, colorReset, configFile)
	fmt.Println()

	errStr := err.Error()

	// Check if it's a file read error
	if strings.Contains(errStr, "failed to read config file") {
		fmt.Printf("  %s%s FILE NOT FOUND%s\n", colorRed, "●", colorReset)
		fmt.Printf("    %sCould not read the configuration file.%s\n", colorDim, colorReset)
		fmt.Printf("    %sPlease check that the file path is correct and the file exists.%s\n", colorDim, colorReset)
		fmt.Println()
		return
	}

	// Check if it's a YAML parse error
	if strings.Contains(errStr, "failed to parse YAML") {
		fmt.Printf("  %s%s YAML SYNTAX ERROR%s\n", colorRed, "●", colorReset)
		fmt.Printf("    %sThe configuration file contains invalid YAML syntax.%s\n", colorDim, colorReset)
		fmt.Println()
		// Extract the actual error message
		parts := strings.SplitN(errStr, ": ", 2)
		if len(parts) > 1 {
			fmt.Printf("    %sDetails:%s %s\n", colorYellow, colorReset, parts[1])
		}
		fmt.Println()
		fmt.Printf("  %sTip:%s Check for proper indentation, missing colons, or unquoted special characters.\n", colorCyan, colorReset)
		fmt.Println()
		return
	}

	// Check if it's a validation error (multiple errors)
	if strings.Contains(errStr, "validation failed with") {
		// Parse the number of errors
		var errorCount int
		fmt.Sscanf(errStr, "configuration validation failed with %d error(s)", &errorCount)

		fmt.Printf("  %s%s VALIDATION FAILED%s %s(%d issue%s found)%s\n",
			colorRed, "●", colorReset,
			colorDim, errorCount, pluralize(errorCount), colorReset)
		fmt.Println()

		// Parse individual errors
		lines := strings.Split(errStr, "\n")
		for _, line := range lines[1:] { // Skip the header line
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Parse error line: "  1. field: message"
			if strings.Contains(line, ". ") {
				parts := strings.SplitN(line, ". ", 2)
				if len(parts) == 2 {
					errorDetail := parts[1]
					// Split field and message
					fieldParts := strings.SplitN(errorDetail, ": ", 2)
					if len(fieldParts) == 2 {
						field := fieldParts[0]
						message := fieldParts[1]

						// Get icon based on field type
						icon := getFieldIcon(field)

						fmt.Printf("    %s %s%s%s\n", icon, colorYellow, field, colorReset)
						fmt.Printf("      %s%s%s\n", colorDim, message, colorReset)
						fmt.Println()
					}
				}
			}
		}

		// Print helpful tips based on common errors
		printValidationTips(errStr)
		return
	}

	// Generic error display
	fmt.Printf("  %s%s ERROR%s\n", colorRed, "●", colorReset)
	fmt.Printf("    %s%s%s\n", colorDim, err.Error(), colorReset)
	fmt.Println()
}

func pluralize(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func getFieldIcon(field string) string {
	return "•"
}

func printValidationTips(errStr string) {
	tips := []string{}

	if strings.Contains(errStr, "port must be between") {
		tips = append(tips, "Port must be a number between 1 and 65535 (common: 8080, 3000, 9000)")
	}
	if strings.Contains(errStr, "name is required") {
		tips = append(tips, "Every app must have a name defined under 'app.name'")
	}
	if strings.Contains(errStr, "path must start with") {
		tips = append(tips, "Endpoint paths must start with '/' (e.g., /api/users)")
	}
	if strings.Contains(errStr, "invalid HTTP method") {
		tips = append(tips, "Valid HTTP methods are: GET, POST, PUT, DELETE, PATCH")
	}
	if strings.Contains(errStr, "invalid placement") {
		tips = append(tips, "Valid placements: query_param, path_param, form_field, json_field, header, cookie")
	}
	if strings.Contains(errStr, "vulnerability type is required") {
		tips = append(tips, "Each vulnerability needs a type (e.g., sql_injection, xss, ssrf)")
	}
	if strings.Contains(errStr, "at least one endpoint") {
		tips = append(tips, "Your config must define at least one endpoint under 'endpoints:'")
	}
	if strings.Contains(errStr, "duplicate") {
		tips = append(tips, "Each endpoint path+method combination must be unique")
	}

	if len(tips) > 0 {
		fmt.Println(colorDim + "  ─────────────────────────────────────────" + colorReset)
		fmt.Printf("  %sTips:%s\n", colorCyan+colorBold, colorReset)
		for _, tip := range tips {
			fmt.Printf("    %s• %s%s\n", colorDim, tip, colorReset)
		}
		fmt.Println()
	}
}
