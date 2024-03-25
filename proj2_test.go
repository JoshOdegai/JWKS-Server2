package main

import (
    "database/sql"
    "testing"
    "fmt"

	
    _ "modernc.org/sqlite" // Import SQLite driver
)

// Function to test the createTableIfNotExists function
func TestCreateTableIfNotExists(t *testing.T) {
    // Create a temporary database for testing
    db, err := sql.Open("sqlite", ":memory:")
    if err != nil {
        t.Fatalf("Failed to open database: %v", err)
    }
    defer db.Close()

    createTableIfNotExists(db)

    // Check if the table was created successfully
    rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'")
    if err != nil {
        t.Fatalf("Error querying table: %v", err)
    }
    defer rows.Close()

    if !rows.Next() {
        t.Error("Table 'keys' not created")
    }
}

//Function to set up a mock test environment
func setupTestEnvironment() (*sql.DB, error) {
    // Create a temporary database for testing
    db, err := sql.Open("sqlite", ":memory:")
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %v", err)
    }

    createTableIfNotExists(db)
    
    // Generate keys
    genKeys()
    
    return db, nil
}



//Function to test main function
func TestMainFunction(t *testing.T) {
    go main()
}
