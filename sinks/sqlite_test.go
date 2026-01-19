package sinks

import (
	"testing"
)

// TestNewSQLite tests SQLite sink creation
func TestNewSQLite(t *testing.T) {
	sink, err := NewSQLite()
	if err != nil {
		t.Fatalf("Failed to create SQLite sink: %v", err)
	}
	defer sink.Close()

	if sink == nil {
		t.Fatal("Expected SQLite sink, got nil")
	}
}

// TestSQLite_CreateTable tests table creation
func TestSQLite_CreateTable(t *testing.T) {
	sink, err := NewSQLite()
	if err != nil {
		t.Fatalf("Failed to create SQLite sink: %v", err)
	}
	defer sink.Close()

	err = sink.CreateTable("test_table", []string{"id", "name", "email"})
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}
}

// TestSQLite_CreateTable_AlreadyExists tests creating a table that already exists
func TestSQLite_CreateTable_AlreadyExists(t *testing.T) {
	sink, err := NewSQLite()
	if err != nil {
		t.Fatalf("Failed to create SQLite sink: %v", err)
	}
	defer sink.Close()

	columns := []string{"id", "name"}

	// Create first time
	err = sink.CreateTable("duplicate_table", columns)
	if err != nil {
		t.Fatalf("Failed to create table first time: %v", err)
	}

	// Create second time (should not error due to IF NOT EXISTS)
	err = sink.CreateTable("duplicate_table", columns)
	if err != nil {
		t.Fatalf("Failed to create table second time: %v", err)
	}
}

// TestSQLite_SeedTable tests data seeding
func TestSQLite_SeedTable(t *testing.T) {
	sink, err := NewSQLite()
	if err != nil {
		t.Fatalf("Failed to create SQLite sink: %v", err)
	}
	defer sink.Close()

	// Seed data (creates table automatically)
	err = sink.SeedTable("seed_test", []string{"id", "name", "value"}, [][]interface{}{
		{"1", "first", "100"},
		{"2", "second", "200"},
		{"3", "third", "300"},
	})
	if err != nil {
		t.Fatalf("Failed to seed table: %v", err)
	}

	// Verify data
	rows, err := sink.Query("SELECT * FROM seed_test ORDER BY id")
	if err != nil {
		t.Fatalf("Failed to query seeded data: %v", err)
	}

	if len(rows) != 3 {
		t.Errorf("Expected 3 rows, got %d", len(rows))
	}
}

// TestSQLite_SeedTable_Empty tests seeding with empty data
func TestSQLite_SeedTable_Empty(t *testing.T) {
	sink, err := NewSQLite()
	if err != nil {
		t.Fatalf("Failed to create SQLite sink: %v", err)
	}
	defer sink.Close()

	// Seed with empty data (should not error)
	err = sink.SeedTable("empty_test", []string{"id"}, [][]interface{}{})
	if err != nil {
		t.Fatalf("Failed to seed empty data: %v", err)
	}
}

// TestSQLite_Query tests query execution
func TestSQLite_Query(t *testing.T) {
	sink, err := NewSQLite()
	if err != nil {
		t.Fatalf("Failed to create SQLite sink: %v", err)
	}
	defer sink.Close()

	// Seed table (creates table automatically)
	err = sink.SeedTable("query_test", []string{"id", "name"}, [][]interface{}{
		{"1", "alice"},
		{"2", "bob"},
	})
	if err != nil {
		t.Fatalf("Failed to seed table: %v", err)
	}

	// Query
	rows, err := sink.Query("SELECT name FROM query_test WHERE id = '1'")
	if err != nil {
		t.Fatalf("Failed to query: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(rows))
	}

	if name, ok := rows[0]["name"].(string); !ok || name != "alice" {
		t.Errorf("Expected name 'alice', got '%v'", rows[0]["name"])
	}
}

// TestSQLite_Query_NoResults tests query with no results
func TestSQLite_Query_NoResults(t *testing.T) {
	sink, err := NewSQLite()
	if err != nil {
		t.Fatalf("Failed to create SQLite sink: %v", err)
	}
	defer sink.Close()

	// Create empty table
	err = sink.CreateTable("empty_query", []string{"id"})
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	rows, err := sink.Query("SELECT * FROM empty_query")
	if err != nil {
		t.Fatalf("Failed to query empty table: %v", err)
	}

	if len(rows) != 0 {
		t.Errorf("Expected 0 rows, got %d", len(rows))
	}
}

// TestSQLite_InsertRow tests single row insertion
func TestSQLite_InsertRow(t *testing.T) {
	sink, err := NewSQLite()
	if err != nil {
		t.Fatalf("Failed to create SQLite sink: %v", err)
	}
	defer sink.Close()

	// Create table
	err = sink.CreateTable("insert_test", []string{"id", "value"})
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Insert rows
	err = sink.InsertRow("insert_test", []string{"id", "value"}, []interface{}{"1", "100"})
	if err != nil {
		t.Fatalf("Failed to insert row: %v", err)
	}

	err = sink.InsertRow("insert_test", []string{"id", "value"}, []interface{}{"2", "200"})
	if err != nil {
		t.Fatalf("Failed to insert row: %v", err)
	}

	// Verify
	rows, err := sink.Query("SELECT * FROM insert_test")
	if err != nil {
		t.Fatalf("Failed to query: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("Expected 2 rows, got %d", len(rows))
	}
}

// TestSQLite_Close tests closing the sink
func TestSQLite_Close(t *testing.T) {
	sink, err := NewSQLite()
	if err != nil {
		t.Fatalf("Failed to create SQLite sink: %v", err)
	}

	err = sink.Close()
	if err != nil {
		t.Errorf("Failed to close SQLite sink: %v", err)
	}
}

// TestSQLite_CloseNil tests closing nil connection
func TestSQLite_CloseNil(t *testing.T) {
	sink := &SQLite{db: nil}
	err := sink.Close()
	if err != nil {
		t.Errorf("Expected no error closing nil db, got: %v", err)
	}
}
