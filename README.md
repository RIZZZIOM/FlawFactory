


<div align="center">

```
███████╗██╗      █████╗ ██╗    ██╗███████╗ █████╗  ██████╗████████╗ ██████╗ ██████╗ ██╗   ██╗
██╔════╝██║     ██╔══██╗██║    ██║██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗╚██╗ ██╔╝
█████╗  ██║     ███████║██║ █╗ ██║█████╗  ███████║██║        ██║   ██║   ██║██████╔╝ ╚████╔╝ 
██╔══╝  ██║     ██╔══██║██║███╗██║██╔══╝  ██╔══██║██║        ██║   ██║   ██║██╔══██╗  ╚██╔╝  
██║     ███████╗██║  ██║╚███╔███╔╝██║     ██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║   ██║   
╚═╝     ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
```

**Config-driven vulnerable web application generator**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

[Getting Started](#getting-started) • [Features](#features) • [Documentation](../../wiki) • [Contributing](CONTRIBUTING.md)

</div>

---

## What is FlawFactory?

FlawFactory is a tool that lets you spin up intentionally vulnerable web applications using simple YAML configs. Instead of hardcoding vulnerabilities or setting up complex environments, you just define what you want in a config file and FlawFactory generates a fully functional vulnerable endpoint.

I built this because I needed a quick way to test WAF rules, validate security scanners, and create reproducible vulnerable environments for training. Existing solutions were either too rigid or required too much setup. With FlawFactory, you describe the vulnerability, and it builds the app.

> **Note: After finalizing the architecture, module design and overall flow, I vibe coded this application with AI assistance. Every feature has been manually tested and validated but the actual code was largely generated through AI.**

## Features

### Vulnerability Modules (9)
- SQL Injection
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- Command Injection
- Path Traversal
- XML External Entity (XXE)
- Insecure Deserialization
- Insecure Direct Object Reference (IDOR)
- NoSQL Injection

### Input Placements (7)
Control exactly where the vulnerable input comes from:
- URL query string
- URL path segment
- POST form data
- JSON body field
- HTTP header
- Cookie value
- Multipart form field

### Sinks (4)
- SQLite database
- Filesystem operations
- Command execution
- HTTP requests

### Configuration
- YAML-based declarative configuration
- Pre-built vulnerability templates in `/templates`
- Configuration validation with detailed errors and warnings
- 4 response types: JSON, HTML, Template, File

### CLI
- `run` - Start the vulnerable server
- `validate` - Validate config without starting
- `modules` - List available vulnerability modules

### Server
- HTTP and HTTPS support
- JSON request logging
- Graceful shutdown
- Port override via CLI

## Getting Started

### Installation

```bash
# Clone the repo
git clone https://github.com/RIZZZIOM/FlawFactory.git
cd FlawFactory

# Build
go build -o flawfactory .
```

Or grab a pre-built binary from the [Releases](https://github.com/RIZZZIOM/FlawFactory/releases/) page.

### Basic Usage

```shell
$ ./flawfactory 

  FlawFactory - Config-driven vulnerable web application generator

  USAGE
    $ flawfactory <command> [flags]

  COMMANDS
    run        Start the vulnerable web server
    validate   Validate config file without starting
    modules    List available vulnerability modules

  EXAMPLES
    # Start server with config
    $ flawfactory run -c config.yaml

    # Start on custom port
    $ flawfactory run -c config.yaml -p 9090

    # Validate configuration
    $ flawfactory validate -c config.yaml

  FLAGS
    -c, --config  path   Path to YAML configuration file
    -p, --port    int    Override port from config
    -h, --help            Show help for a command

  Run 'flawfactory <command> -h' for more information on a command

```

- **Start a server**

```
./flawfactory run -c <TEMPLATE>.yaml 

    ███████╗██╗      █████╗ ██╗    ██╗███████╗ █████╗  ██████╗████████╗ ██████╗ ██████╗ ██╗   ██╗                                                            
    ██╔════╝██║     ██╔══██╗██║    ██║██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗╚██╗ ██╔╝                                                            
    █████╗  ██║     ███████║██║ █╗ ██║█████╗  ███████║██║        ██║   ██║   ██║██████╔╝ ╚████╔╝                                                             
    ██╔══╝  ██║     ██╔══██║██║███╗██║██╔══╝  ██╔══██║██║        ██║   ██║   ██║██╔══██╗  ╚██╔╝                                                              
    ██║     ███████╗██║  ██║╚███╔███╔╝██║     ██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║   ██║                                                               
    ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝   ╚═╝                                                               
                                                                                                                                                             
    ─────────────────────────────────────────────────────────────────────────────────────────
                        Config-driven vulnerable web application generator
                                          Version 1.0

2026/01/19 05:03:54 Initialized SQLite sink (in-memory)
2026/01/19 05:03:54 Seeded table 'bikes' with 3 rows
2026/01/19 05:03:54 Seeded table 'users' with 4 rows
2026/01/19 05:03:54 Seeded table 'cars' with 5 rows
2026/01/19 05:03:54 Request logs will be saved to: log/sql_injection.json
2026/01/19 05:03:54 Registered route: GET /health
2026/01/19 05:03:54 Registered route: GET /error/query
2026/01/19 05:03:54 Registered route: GET /blind/query
2026/01/19 05:03:54 Registered route: GET /error/path/{id}
2026/01/19 05:03:54 Registered route: GET /blind/path/{sr}
2026/01/19 05:03:54 Registered route: POST /error/form
2026/01/19 05:03:54 Registered route: POST /blind/form
2026/01/19 05:03:54 Registered route: POST /error/json
2026/01/19 05:03:54 Registered route: POST /blind/json
2026/01/19 05:03:54 Registered route: GET /error/header
2026/01/19 05:03:54 Registered route: GET /blind/header
2026/01/19 05:03:54 Registered route: GET /error/cookie
2026/01/19 05:03:54 Registered route: GET /blind/cookie
┌─────────────────────────────────────────┐
│         CONFIGURATION SUMMARY           │
└─────────────────────────────────────────┘

  ◆ APPLICATION
    Name:        SQL Injection Example Lab
    Host:        0.0.0.0
    Port:        8081

  ◆ RESOURCES
    Endpoints:   12
    Tables:      3

  ◆ VULNERABILITIES
    • sql_injection        12

  ─────────────────────────────────────────
  ✓ Server ready at: http://0.0.0.0:8081
  ─────────────────────────────────────────

2026/01/19 05:03:54 FlawFactory starting on http://0.0.0.0:8081
```

- **Validate a config**

```shell
./flawfactory validate -c <TEMPLATE>.yaml 

  ✓ Configuration Valid
  ─────────────────────────────────────────

  SUMMARY
    App Name:    Command Injection Example Lab
    Port:        8084
    Endpoints:   30
    Vulnerabilities: 30

```

- **List available modules**

```shell
./flawfactory modules                                     

┌─────────────────────────────────────────┐
│       AVAILABLE VULNERABILITY MODULES   │
└─────────────────────────────────────────┘

  • idor
     Description: Insecure Direct Object Reference - access control bypass via parameter manipulation
     Placements:  [query_param path_param form_field json_field header cookie]
     Requires:    sqlite sink

  • path_traversal
     Description: Path Traversal vulnerability for reading arbitrary files
     Placements:  [query_param path_param form_field json_field multipart-form]
     Requires:    filesystem sink

  • xss_reflected
     Description: Reflected Cross-Site Scripting with multiple contexts (body, attribute, script)
     Placements:  [query_param path_param form_field json_field header]

  • xxe
     Description: XML External Entity (XXE) vulnerability that allows reading files, SSRF, and denial of service through malicious XML
     Placements:  [query_param form_field json_field header cookie]

  • command_injection
     Description: OS Command Injection vulnerability for executing arbitrary commands
     Placements:  [query_param path_param form_field json_field header]
     Requires:    command sink

  • insecure_deserialization
     Description: Insecure Deserialization vulnerability that emulates processing of Java/PHP serialized objects
     Placements:  [query_param form_field json_field header cookie]

  • nosql_injection
     Description: NoSQL Injection vulnerability that emulates MongoDB and Redis query injection
     Placements:  [query_param path_param form_field json_field header cookie]

  • sql_injection
     Description: SQL Injection vulnerability with multiple variants (error_based, blind_boolean)
     Placements:  [query_param path_param form_field json_field header cookie]
     Requires:    sqlite sink

  • ssrf
     Description: Server-Side Request Forgery vulnerability for making arbitrary HTTP requests
     Placements:  [query_param form_field json_field header]
     Requires:    http sink

```

### Example Templates

Check out the `/templates` directory for ready-to-use configs for each vulnerability module. These are a good starting point to understand how each module works and can be modified for your specific use case.

## User Guide

For the complete usage guide, configuration reference, and detailed module documentation, check out the [Wiki](https://github.com/RIZZZIOM/FlawFactory/wiki).

## Contributing

Contributions are welcome! Whether it's new vulnerability modules, bug fixes, or documentation improvements - I'd appreciate the help.

Please read the [Contributing Guidelines]() before submitting a PR.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE] file for details.

---

<div align="center">

**Built for security testing and education purposes only.**

Use responsibly. Don't deploy vulnerable applications in production environments.

</div>






