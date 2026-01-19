package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestNew tests server creation
func TestNew(t *testing.T) {
	srv, err := New("127.0.0.1", 8080, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	if srv == nil {
		t.Fatal("Expected server to be created, got nil")
	}

	if srv.httpServer == nil {
		t.Fatal("Expected httpServer to be initialized, got nil")
	}

	if srv.router == nil {
		t.Fatal("Expected router to be initialized, got nil")
	}

	expectedAddr := "127.0.0.1:8080"
	if srv.httpServer.Addr != expectedAddr {
		t.Errorf("Expected address '%s', got '%s'", expectedAddr, srv.httpServer.Addr)
	}
}

// TestServer_Router tests getting the router
func TestServer_Router(t *testing.T) {
	srv, err := New("127.0.0.1", 8080, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	router := srv.Router()

	if router == nil {
		t.Fatal("Expected router, got nil")
	}

	if router != srv.router {
		t.Error("Expected Router() to return the same router instance")
	}
}

// TestServer_StartStop tests starting and stopping the server
func TestServer_StartStop(t *testing.T) {
	// Use a random available port
	srv, err := New("127.0.0.1", 0, "", nil) // Port 0 means random available port
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Add a test endpoint
	srv.Router().HandleFunc("GET", "/test", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Start()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Get the actual port (since we used 0)
	// Note: This is a limitation - we can't easily get the random port
	// In real tests, you'd use a fixed port or httptest.Server

	// Stop the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Stop(ctx); err != nil {
		t.Errorf("Server stop failed: %v", err)
	}

	// Check that Start() returned without error
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Server start failed: %v", err)
		}
	case <-time.After(1 * time.Second):
		// Timeout is okay - server might still be shutting down
	}
}

// TestServer_Integration tests full server lifecycle with real HTTP requests
func TestServer_Integration(t *testing.T) {
	// Create server with a known port
	port := 18080 // Use a high port to avoid conflicts
	srv, err := New("127.0.0.1", port, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Register test endpoint
	srv.Router().HandleFunc("GET", "/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	srv.Router().HandleFunc("POST", "/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	})

	// Start server
	go func() {
		if err := srv.Start(); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()

	// Wait for server to be ready
	time.Sleep(200 * time.Millisecond)

	// Test GET request
	t.Run("GET /health", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/health", port))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		expected := `{"status":"healthy"}`
		if string(body) != expected {
			t.Errorf("Expected body '%s', got '%s'", expected, string(body))
		}
	})

	// Test POST request
	t.Run("POST /echo", func(t *testing.T) {
		resp, err := http.Post(
			fmt.Sprintf("http://localhost:%d/echo", port),
			"text/plain",
			io.NopCloser(io.Reader(io.NopCloser(http.NoBody))),
		)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()
	})

	// Test 404
	t.Run("GET /notfound", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/notfound", port))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status 404, got %d", resp.StatusCode)
		}
	})

	// Shutdown server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Stop(ctx); err != nil {
		t.Errorf("Server stop failed: %v", err)
	}

	// Verify server is actually stopped
	time.Sleep(100 * time.Millisecond)
	_, err = http.Get(fmt.Sprintf("http://localhost:%d/health", port))
	if err == nil {
		t.Error("Expected error when connecting to stopped server, got nil")
	}
}

// TestServer_GracefulShutdown tests that shutdown waits for requests
func TestServer_GracefulShutdown(t *testing.T) {
	port := 18081
	srv, err := New("127.0.0.1", port, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Add endpoint with artificial delay
	srv.Router().HandleFunc("GET", "/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Write([]byte("done"))
	})

	// Start server
	go srv.Start()
	time.Sleep(100 * time.Millisecond)

	// Start a slow request
	requestDone := make(chan bool)
	go func() {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/slow", port))
		if err != nil {
			t.Logf("Request error: %v", err)
			requestDone <- false
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if string(body) == "done" {
			requestDone <- true
		} else {
			requestDone <- false
		}
	}()

	// Give request time to start
	time.Sleep(50 * time.Millisecond)

	// Initiate shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	shutdownDone := make(chan bool)
	go func() {
		srv.Stop(ctx)
		shutdownDone <- true
	}()

	// Wait for request to complete
	select {
	case success := <-requestDone:
		if !success {
			t.Error("Request did not complete successfully during graceful shutdown")
		}
	case <-time.After(1 * time.Second):
		t.Error("Request did not complete within expected time")
	}

	// Wait for shutdown to complete
	select {
	case <-shutdownDone:
		// Good - shutdown completed
	case <-time.After(1 * time.Second):
		t.Error("Shutdown did not complete within expected time")
	}
}

// TestServer_Timeouts tests that server has proper timeouts configured
func TestServer_Timeouts(t *testing.T) {
	srv, err := New("127.0.0.1", 8080, "", nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	if srv.httpServer.ReadTimeout != 15*time.Second {
		t.Errorf("Expected ReadTimeout 15s, got %v", srv.httpServer.ReadTimeout)
	}

	if srv.httpServer.WriteTimeout != 15*time.Second {
		t.Errorf("Expected WriteTimeout 15s, got %v", srv.httpServer.WriteTimeout)
	}

	if srv.httpServer.IdleTimeout != 60*time.Second {
		t.Errorf("Expected IdleTimeout 60s, got %v", srv.httpServer.IdleTimeout)
	}
}
