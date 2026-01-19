package sinks

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// SQLite provides an in-memory SQLite database for SQL injection testing
type SQLite struct {
	db *sql.DB
}

// NewSQLite creates a new in-memory SQLite database
func NewSQLite() (*SQLite, error) {
	// Use in-memory database
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping SQLite: %w", err)
	}

	return &SQLite{db: db}, nil
}

// Close closes the database connection
func (s *SQLite) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreateTable creates a table with the specified columns
func (s *SQLite) CreateTable(tableName string, columns []string) error {
	// Build column definitions (all TEXT for simplicity)
	colDefs := make([]string, len(columns))
	for i, col := range columns {
		colDefs[i] = fmt.Sprintf("%s TEXT", col)
	}

	query := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)",
		tableName, strings.Join(colDefs, ", "))

	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create table %s: %w", tableName, err)
	}

	return nil
}

// InsertRow inserts a row into a table
func (s *SQLite) InsertRow(tableName string, columns []string, values []interface{}) error {
	// Build placeholders
	placeholders := make([]string, len(values))
	for i := range values {
		placeholders[i] = "?"
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		tableName,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "))

	_, err := s.db.Exec(query, values...)
	if err != nil {
		return fmt.Errorf("failed to insert row: %w", err)
	}

	return nil
}

// SeedTable creates a table and populates it with data
func (s *SQLite) SeedTable(tableName string, columns []string, rows [][]interface{}) error {
	// Create the table
	if err := s.CreateTable(tableName, columns); err != nil {
		return err
	}

	// Insert rows
	for i, row := range rows {
		if err := s.InsertRow(tableName, columns, row); err != nil {
			return fmt.Errorf("failed to insert row %d: %w", i, err)
		}
	}

	return nil
}

// Query executes a SQL query and returns results as a slice of maps
// This is intentionally vulnerable - it executes raw SQL
func (s *SQLite) Query(query string) ([]map[string]interface{}, error) {
	rows, err := s.db.Query(query)
	if err != nil {
		// Return the SQL error for error-based injection
		return nil, fmt.Errorf("SQL error: %w", err)
	}
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}

	var results []map[string]interface{}

	for rows.Next() {
		// Create a slice of interface{} to hold the values
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Convert to map
		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			// Convert []byte to string for readability
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		results = append(results, row)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return results, nil
}

// Exec executes a SQL statement (INSERT, UPDATE, DELETE, etc.)
func (s *SQLite) Exec(statement string) error {
	_, err := s.db.Exec(statement)
	if err != nil {
		return fmt.Errorf("SQL error: %w", err)
	}
	return nil
}

// QuerySingle executes a query and returns a single value
// Useful for blind boolean-based injection checks
func (s *SQLite) QuerySingle(query string) (interface{}, error) {
	var result interface{}
	err := s.db.QueryRow(query).Scan(&result)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("SQL error: %w", err)
	}

	// Convert []byte to string
	if b, ok := result.([]byte); ok {
		return string(b), nil
	}
	return result, nil
}
