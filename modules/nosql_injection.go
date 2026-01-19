package modules

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// NoSQLInjection implements the nosql_injection vulnerability module
type NoSQLInjection struct{}

// init registers the module
func init() {
	Register(&NoSQLInjection{})
}

// Info returns module metadata
func (m *NoSQLInjection) Info() ModuleInfo {
	return ModuleInfo{
		Name:        "nosql_injection",
		Description: "NoSQL Injection vulnerability that emulates MongoDB and Redis query injection",
		SupportedPlacements: []string{
			"query_param",
			"path_param",
			"form_field",
			"json_field",
			"header",
			"cookie",
		},
		RequiresSink: "", // No external sink required - emulates NoSQL behavior
		ValidVariants: map[string][]string{
			"database":  {"mongodb", "mongo", "redis"},
			"operation": {"find", "findOne", "aggregate", "update", "updateOne", "updateMany", "delete", "deleteOne", "deleteMany", "insert", "insertOne", "get", "set", "hget", "hgetall", "lpush", "rpush", "lrange", "smembers", "zadd", "zrange", "exists", "del", "incr", "decr", "ttl", "ping", "info"},
		},
	}
}

// NoSQLResult represents the result of a NoSQL query
type NoSQLResult struct {
	Database      string                   `json:"database"`
	Operation     string                   `json:"operation,omitempty"`
	Query         interface{}              `json:"query,omitempty"`
	InjectionType string                   `json:"injection_type,omitempty"`
	Exploitable   bool                     `json:"exploitable"`
	Results       []map[string]interface{} `json:"results,omitempty"`
	Count         int                      `json:"count,omitempty"`
	Error         string                   `json:"error,omitempty"`
	Warning       string                   `json:"warning,omitempty"`
	RawInput      string                   `json:"raw_input,omitempty"`
	ExecutedCmd   string                   `json:"executed_command,omitempty"`
}

// Handle processes the request and emulates NoSQL database behavior
func (m *NoSQLInjection) Handle(ctx *HandlerContext) (*Result, error) {
	// Get configuration
	database := ctx.GetConfigString("database", "mongodb")
	collection := ctx.GetConfigString("collection", "users")
	operation := ctx.GetConfigString("operation", "find")
	queryTemplate := ctx.GetConfigString("query_template", "")
	showErrors := ctx.GetConfigBool("show_errors", true)

	input := ctx.Input

	// Process based on database type
	var result *NoSQLResult
	switch strings.ToLower(database) {
	case "mongodb", "mongo":
		result = processMongoDBQuery(input, collection, operation, queryTemplate, showErrors)
	case "redis":
		result = processRedisCommand(input, operation, queryTemplate, showErrors)
	default:
		result = processMongoDBQuery(input, collection, operation, queryTemplate, showErrors)
	}

	return NewResult(result), nil
}

// =============================================================================
// MongoDB Emulation
// =============================================================================

// processMongoDBQuery emulates MongoDB query processing
func processMongoDBQuery(input, collection, operation, queryTemplate string, showErrors bool) *NoSQLResult {
	result := &NoSQLResult{
		Database:  "mongodb",
		Operation: operation,
		RawInput:  input,
	}

	// Build the query
	var query interface{}
	var queryStr string

	if queryTemplate != "" {
		queryStr = strings.ReplaceAll(queryTemplate, "{input}", input)
	} else {
		queryStr = input
	}

	// Try to parse as JSON
	err := json.Unmarshal([]byte(queryStr), &query)
	if err != nil {
		// If not valid JSON, treat as field value injection
		query = map[string]interface{}{
			"username": input,
		}
		queryStr = fmt.Sprintf(`{"username": "%s"}`, input)
	}

	result.Query = query

	// Detect injection patterns
	injectionType, exploitable := detectMongoDBInjection(input, queryStr)
	result.InjectionType = injectionType
	result.Exploitable = exploitable

	if exploitable {
		result.Warning = fmt.Sprintf("MongoDB %s injection detected", injectionType)
	}

	// Emulate query results based on operation and injection
	switch operation {
	case "find", "findOne":
		result.Results, result.Count = emulateMongoFind(collection, query, injectionType, exploitable)
	case "aggregate":
		result.Results, result.Count = emulateMongoAggregate(collection, query, exploitable)
	case "update", "updateOne", "updateMany":
		result.Results, result.Count = emulateMongoUpdate(collection, query, exploitable)
	case "delete", "deleteOne", "deleteMany":
		result.Results, result.Count = emulateMongoDelete(collection, query, exploitable)
	case "insert", "insertOne":
		result.Results, result.Count = emulateMongoInsert(collection, query)
	default:
		result.Results, result.Count = emulateMongoFind(collection, query, injectionType, exploitable)
	}

	return result
}

// detectMongoDBInjection detects MongoDB injection patterns
func detectMongoDBInjection(input, queryStr string) (string, bool) {
	// Check for operator injection ($ne, $gt, $where, etc.)
	operatorPatterns := map[string]string{
		`\$ne`:          "operator_ne",
		`\$gt`:          "operator_gt",
		`\$gte`:         "operator_gte",
		`\$lt`:          "operator_lt",
		`\$lte`:         "operator_lte",
		`\$in`:          "operator_in",
		`\$nin`:         "operator_nin",
		`\$or`:          "operator_or",
		`\$and`:         "operator_and",
		`\$not`:         "operator_not",
		`\$nor`:         "operator_nor",
		`\$exists`:      "operator_exists",
		`\$regex`:       "operator_regex",
		`\$where`:       "javascript_injection",
		`\$expr`:        "expression_injection",
		`\$function`:    "javascript_injection",
		`\$accumulator`: "javascript_injection",
	}

	combined := input + queryStr
	for pattern, injType := range operatorPatterns {
		if matched, _ := regexp.MatchString(pattern, combined); matched {
			// $where and JavaScript execution are most dangerous
			if strings.Contains(injType, "javascript") {
				return injType, true
			}
			return injType, true
		}
	}

	// Check for JavaScript injection patterns
	jsPatterns := []string{
		`this\.`,
		`function\s*\(`,
		`return\s+`,
		`sleep\s*\(`,
		`db\.`,
		`process\.`,
		`require\s*\(`,
	}
	for _, pattern := range jsPatterns {
		if matched, _ := regexp.MatchString(pattern, combined); matched {
			return "javascript_injection", true
		}
	}

	// Check for JSON injection (breaking out of string context)
	jsonBreakPatterns := []string{
		`['"]\s*[:,}\]]\s*[{[]?\s*['"$]`, // Breaking out of string
		`['"]\s*:\s*['"$]`,               // Key injection
	}
	for _, pattern := range jsonBreakPatterns {
		if matched, _ := regexp.MatchString(pattern, input); matched {
			return "json_injection", true
		}
	}

	// Check for authentication bypass patterns
	if strings.Contains(input, `"$ne"`) || strings.Contains(input, `{"$gt":""}`) ||
		strings.Contains(input, `"$exists":true`) {
		return "auth_bypass", true
	}

	return "none", false
}

// emulateMongoFind emulates MongoDB find operation
func emulateMongoFind(collection string, query interface{}, injType string, exploitable bool) ([]map[string]interface{}, int) {
	// Sample data based on collection
	sampleData := getMongoSampleData(collection)

	if exploitable {
		// If injection detected, return all data (auth bypass simulation)
		switch injType {
		case "operator_ne", "auth_bypass", "operator_gt", "operator_exists":
			// $ne:null or $gt:"" bypasses return all records
			return sampleData, len(sampleData)
		case "javascript_injection":
			// JavaScript injection could expose all data
			return sampleData, len(sampleData)
		case "operator_regex":
			// Regex could match multiple records
			return sampleData[:min(2, len(sampleData))], min(2, len(sampleData))
		}
	}

	// Normal query - return first matching record
	if len(sampleData) > 0 {
		return sampleData[:1], 1
	}
	return nil, 0
}

// emulateMongoAggregate emulates MongoDB aggregate operation
func emulateMongoAggregate(collection string, query interface{}, exploitable bool) ([]map[string]interface{}, int) {
	if exploitable {
		// Aggregation with injection might expose statistics or all data
		return []map[string]interface{}{
			{
				"_id":   nil,
				"count": 150,
				"data":  getMongoSampleData(collection),
			},
		}, 1
	}

	return []map[string]interface{}{
		{
			"_id":   "result",
			"count": 1,
		},
	}, 1
}

// emulateMongoUpdate emulates MongoDB update operation
func emulateMongoUpdate(collection string, query interface{}, exploitable bool) ([]map[string]interface{}, int) {
	if exploitable {
		// Injection in update could modify multiple records
		return []map[string]interface{}{
			{
				"acknowledged":  true,
				"matchedCount":  100,
				"modifiedCount": 100,
				"warning":       "Mass update detected - injection may have affected all records",
			},
		}, 100
	}

	return []map[string]interface{}{
		{
			"acknowledged":  true,
			"matchedCount":  1,
			"modifiedCount": 1,
		},
	}, 1
}

// emulateMongoDelete emulates MongoDB delete operation
func emulateMongoDelete(collection string, query interface{}, exploitable bool) ([]map[string]interface{}, int) {
	if exploitable {
		// Injection in delete could remove all records
		return []map[string]interface{}{
			{
				"acknowledged": true,
				"deletedCount": 100,
				"warning":      "Mass deletion detected - injection may have deleted all records",
			},
		}, 100
	}

	return []map[string]interface{}{
		{
			"acknowledged": true,
			"deletedCount": 1,
		},
	}, 1
}

// emulateMongoInsert emulates MongoDB insert operation
func emulateMongoInsert(collection string, query interface{}) ([]map[string]interface{}, int) {
	return []map[string]interface{}{
		{
			"acknowledged": true,
			"insertedId":   "507f1f77bcf86cd799439011",
		},
	}, 1
}

// getMongoSampleData returns sample data for a collection
func getMongoSampleData(collection string) []map[string]interface{} {
	switch collection {
	case "users":
		return []map[string]interface{}{
			{"_id": "507f1f77bcf86cd799439011", "username": "admin", "email": "admin@example.com", "role": "administrator", "password_hash": "$2b$12$LQv3c1yqBw..."},
			{"_id": "507f1f77bcf86cd799439012", "username": "john", "email": "john@example.com", "role": "user", "password_hash": "$2b$12$xyz..."},
			{"_id": "507f1f77bcf86cd799439013", "username": "jane", "email": "jane@example.com", "role": "user", "password_hash": "$2b$12$abc..."},
		}
	case "products":
		return []map[string]interface{}{
			{"_id": "prod001", "name": "Widget", "price": 9.99, "stock": 100},
			{"_id": "prod002", "name": "Gadget", "price": 19.99, "stock": 50},
			{"_id": "prod003", "name": "Secret Product", "price": 999.99, "stock": 5, "internal": true},
		}
	case "sessions":
		return []map[string]interface{}{
			{"_id": "sess001", "user_id": "507f1f77bcf86cd799439011", "token": "eyJhbGciOiJIUzI1NiIs...", "expires": "2026-12-31"},
			{"_id": "sess002", "user_id": "507f1f77bcf86cd799439012", "token": "eyJhbGciOiJIUzI1NiIs...", "expires": "2026-12-31"},
		}
	case "orders":
		return []map[string]interface{}{
			{"_id": "ord001", "user_id": "507f1f77bcf86cd799439012", "total": 29.98, "status": "completed"},
			{"_id": "ord002", "user_id": "507f1f77bcf86cd799439013", "total": 9.99, "status": "pending"},
		}
	default:
		return []map[string]interface{}{
			{"_id": "doc001", "data": "sample document 1"},
			{"_id": "doc002", "data": "sample document 2"},
			{"_id": "doc003", "data": "sensitive data", "internal": true},
		}
	}
}

// =============================================================================
// Redis Emulation
// =============================================================================

// processRedisCommand emulates Redis command processing
func processRedisCommand(input, operation, commandTemplate string, showErrors bool) *NoSQLResult {
	result := &NoSQLResult{
		Database:  "redis",
		Operation: operation,
		RawInput:  input,
	}

	// Build the command
	var command string
	if commandTemplate != "" {
		command = strings.ReplaceAll(commandTemplate, "{input}", input)
	} else {
		command = input
	}

	result.ExecutedCmd = command

	// Detect injection patterns
	injectionType, exploitable := detectRedisInjection(input, command)
	result.InjectionType = injectionType
	result.Exploitable = exploitable

	if exploitable {
		result.Warning = fmt.Sprintf("Redis %s detected", injectionType)
	}

	// Parse and emulate the command
	results, count := emulateRedisCommand(command, injectionType, exploitable)
	result.Results = results
	result.Count = count

	return result
}

// detectRedisInjection detects Redis injection patterns
func detectRedisInjection(input, command string) (string, bool) {
	combined := strings.ToUpper(input + " " + command)
	combinedOriginal := input + " " + command // Keep original case for Lua patterns

	// Check for CRLF injection first (highest priority)
	if strings.Contains(input, "\r\n") || strings.Contains(input, "\n") {
		return "crlf_injection", true
	}

	// Check for command chaining with escaped CRLF
	if strings.Contains(input, "\\r\\n") {
		return "command_chaining", true
	}

	// Check for Lua code patterns (case-sensitive)
	luaPatterns := []string{
		`redis\.call`,
		`redis\.pcall`,
		`loadstring`,
		`dofile`,
		`os\.execute`,
		`io\.popen`,
	}
	for _, pattern := range luaPatterns {
		if matched, _ := regexp.MatchString(pattern, combinedOriginal); matched {
			return "lua_injection", true
		}
	}

	// Dangerous command patterns
	dangerousCommands := map[string]string{
		`\bEVAL\b`:       "lua_injection",
		`\bEVALSHA\b`:    "lua_injection",
		`\bSCRIPT\b`:     "script_injection",
		`\bCONFIG\b`:     "config_manipulation",
		`\bFLUSHALL\b`:   "data_destruction",
		`\bFLUSHDB\b`:    "data_destruction",
		`\bSHUTDOWN\b`:   "server_shutdown",
		`\bDEBUG\b`:      "debug_command",
		`\bSLAVEOF\b`:    "replication_attack",
		`\bREPLICATOF\b`: "replication_attack",
		`\bMODULE\b`:     "module_loading",
		`\bKEYS\s+\*`:    "key_enumeration",
		`\bSCAN\b`:       "key_enumeration",
	}

	for pattern, injType := range dangerousCommands {
		if matched, _ := regexp.MatchString(pattern, combined); matched {
			return injType, true
		}
	}

	return "none", false
}

// emulateRedisCommand emulates Redis command execution
func emulateRedisCommand(command string, injType string, exploitable bool) ([]map[string]interface{}, int) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return nil, 0
	}

	cmd := strings.ToUpper(parts[0])

	// If exploitable, return dangerous results
	if exploitable {
		return emulateExploitedRedisCommand(cmd, command, injType)
	}

	// Normal command emulation
	return emulateNormalRedisCommand(cmd, parts)
}

// emulateExploitedRedisCommand returns results for exploited commands
func emulateExploitedRedisCommand(cmd, fullCommand, injType string) ([]map[string]interface{}, int) {
	switch injType {
	case "key_enumeration":
		return []map[string]interface{}{
			{
				"keys": []string{
					"user:1", "user:2", "user:admin",
					"session:abc123", "session:xyz789",
					"config:secret", "api_key:production",
				},
				"warning": "Key enumeration exposed sensitive key names",
			},
		}, 7
	case "config_manipulation":
		return []map[string]interface{}{
			{
				"result":  "OK",
				"warning": "Config command executed - potential RCE via dir/dbfilename",
				"config_dump": map[string]string{
					"dir":         "/var/lib/redis",
					"dbfilename":  "dump.rdb",
					"requirepass": "",
				},
			},
		}, 1
	case "lua_injection":
		return []map[string]interface{}{
			{
				"result":  "Lua script executed",
				"warning": "Lua injection detected - arbitrary code execution possible",
				"output":  "Script returned: sensitive_data_here",
			},
		}, 1
	case "data_destruction":
		return []map[string]interface{}{
			{
				"result":  "OK",
				"warning": "FLUSHALL/FLUSHDB executed - all data destroyed",
				"deleted": 15000,
			},
		}, 1
	case "crlf_injection", "command_chaining":
		return []map[string]interface{}{
			{
				"result":  "Multiple commands executed",
				"warning": "CRLF injection allowed command chaining",
				"commands_executed": []string{
					"GET user:1",
					"CONFIG SET dir /tmp",
					"CONFIG SET dbfilename shell.php",
				},
			},
		}, 3
	default:
		return []map[string]interface{}{
			{
				"result":  "Command executed",
				"warning": "Potential injection detected",
			},
		}, 1
	}
}

// emulateNormalRedisCommand emulates normal Redis command responses
func emulateNormalRedisCommand(cmd string, parts []string) ([]map[string]interface{}, int) {
	switch cmd {
	case "GET":
		key := ""
		if len(parts) > 1 {
			key = parts[1]
		}
		return []map[string]interface{}{
			{"key": key, "value": getRedisSampleValue(key)},
		}, 1
	case "SET":
		return []map[string]interface{}{
			{"result": "OK"},
		}, 1
	case "HGET", "HGETALL":
		return []map[string]interface{}{
			{
				"hash": map[string]string{
					"field1": "value1",
					"field2": "value2",
				},
			},
		}, 1
	case "LPUSH", "RPUSH":
		return []map[string]interface{}{
			{"result": 5}, // New list length
		}, 1
	case "LRANGE":
		return []map[string]interface{}{
			{"list": []string{"item1", "item2", "item3"}},
		}, 3
	case "SMEMBERS":
		return []map[string]interface{}{
			{"members": []string{"member1", "member2"}},
		}, 2
	case "ZADD", "ZRANGE":
		return []map[string]interface{}{
			{"sorted_set": []map[string]interface{}{
				{"member": "item1", "score": 1.0},
				{"member": "item2", "score": 2.0},
			}},
		}, 2
	case "EXISTS":
		return []map[string]interface{}{
			{"exists": true, "count": 1},
		}, 1
	case "DEL":
		return []map[string]interface{}{
			{"deleted": 1},
		}, 1
	case "INCR", "DECR":
		return []map[string]interface{}{
			{"value": 42},
		}, 1
	case "TTL":
		return []map[string]interface{}{
			{"ttl": 3600},
		}, 1
	case "PING":
		return []map[string]interface{}{
			{"result": "PONG"},
		}, 1
	case "INFO":
		return []map[string]interface{}{
			{
				"redis_version":     "6.2.0",
				"connected_clients": 10,
				"used_memory_human": "1.5M",
			},
		}, 1
	default:
		return []map[string]interface{}{
			{"result": "OK"},
		}, 1
	}
}

// getRedisSampleValue returns sample value for a Redis key
func getRedisSampleValue(key string) interface{} {
	sampleData := map[string]interface{}{
		"user:1":             `{"id":1,"username":"john","email":"john@example.com"}`,
		"user:admin":         `{"id":0,"username":"admin","email":"admin@example.com","role":"superuser"}`,
		"session:abc123":     `{"user_id":1,"expires":"2026-12-31T23:59:59Z"}`,
		"config:secret":      "supersecretapikey12345",
		"api_key:production": "sk_live_abc123xyz789",
		"counter:visits":     "15234",
	}

	if val, ok := sampleData[key]; ok {
		return val
	}
	return "sample_value"
}

// =============================================================================
// Utility Functions
// =============================================================================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SimulateMongoDBDelay simulates time-based injection for blind attacks
func SimulateMongoDBDelay(query string) time.Duration {
	// Check for sleep patterns in $where
	sleepPattern := regexp.MustCompile(`sleep\s*\(\s*(\d+)\s*\)`)
	if matches := sleepPattern.FindStringSubmatch(query); len(matches) > 1 {
		if ms, err := strconv.Atoi(matches[1]); err == nil {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return 0
}
