package sinks

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNewHTTP tests HTTP sink creation
func TestNewHTTP(t *testing.T) {
	sink := NewHTTP()
	if sink == nil {
		t.Fatal("Expected HTTP sink, got nil")
	}
}

// TestNewHTTPWithOptions tests HTTP sink with custom options
func TestNewHTTPWithOptions(t *testing.T) {
	sink := NewHTTPWithOptions(10*time.Second, true)
	if sink == nil {
		t.Fatal("Expected HTTP sink, got nil")
	}
}

// TestHTTP_Fetch tests GET request
func TestHTTP_Fetch(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	sink := NewHTTP()
	resp, err := sink.Fetch(server.URL)

	if err != nil {
		t.Fatalf("Failed to make GET request: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if resp.Body != "success" {
		t.Errorf("Expected body 'success', got '%s'", resp.Body)
	}
}

// TestHTTP_FetchWithOptions tests fetch with custom options
func TestHTTP_FetchWithOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fetched"))
	}))
	defer server.Close()

	sink := NewHTTP()
	opts := HTTPOptions{
		Method:          "GET",
		FollowRedirects: true,
		Timeout:         30,
	}

	resp, err := sink.FetchWithOptions(server.URL, opts)
	if err != nil {
		t.Fatalf("Failed to fetch with options: %v", err)
	}

	if resp.Body != "fetched" {
		t.Errorf("Expected body 'fetched', got '%s'", resp.Body)
	}
}

// TestHTTP_FetchWithOptions_Headers tests fetch with custom headers
func TestHTTP_FetchWithOptions_Headers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customHeader := r.Header.Get("X-Custom-Header")
		if customHeader != "test-value" {
			t.Errorf("Expected X-Custom-Header 'test-value', got '%s'", customHeader)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink := NewHTTP()
	opts := HTTPOptions{
		Method: "GET",
		Headers: map[string]string{
			"X-Custom-Header": "test-value",
		},
	}

	_, err := sink.FetchWithOptions(server.URL, opts)
	if err != nil {
		t.Fatalf("Failed to fetch with headers: %v", err)
	}
}

// TestHTTP_FetchWithOptions_POST tests POST request
func TestHTTP_FetchWithOptions_POST(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created"))
	}))
	defer server.Close()

	sink := NewHTTP()
	opts := HTTPOptions{
		Method: "POST",
		Body:   `{"key":"value"}`,
	}

	resp, err := sink.FetchWithOptions(server.URL, opts)
	if err != nil {
		t.Fatalf("Failed to make POST request: %v", err)
	}

	if resp.StatusCode != 201 {
		t.Errorf("Expected status 201, got %d", resp.StatusCode)
	}
}

// TestHTTP_FetchWithOptions_PUT tests PUT request
func TestHTTP_FetchWithOptions_PUT(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("Expected PUT method, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink := NewHTTP()
	opts := HTTPOptions{
		Method: "PUT",
		Body:   `{"update":"data"}`,
	}

	_, err := sink.FetchWithOptions(server.URL, opts)
	if err != nil {
		t.Fatalf("Failed to make PUT request: %v", err)
	}
}

// TestHTTP_FollowRedirects tests redirect following
func TestHTTP_FollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("final destination"))
	}))
	defer server.Close()

	sink := NewHTTP() // Default follows redirects
	resp, err := sink.Fetch(server.URL + "/redirect")
	if err != nil {
		t.Fatalf("Failed to follow redirect: %v", err)
	}

	if resp.Body != "final destination" {
		t.Errorf("Expected 'final destination', got '%s'", resp.Body)
	}
}

// TestHTTP_NoFollowRedirects tests redirect not followed
func TestHTTP_NoFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer server.Close()

	sink := NewHTTP()
	// Use FetchWithOptions with FollowRedirects: false to not follow redirects
	resp, err := sink.FetchWithOptions(server.URL, HTTPOptions{
		Method:          "GET",
		FollowRedirects: false,
		Timeout:         5,
	})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Should get redirect status, not follow it
	if resp.StatusCode != 302 {
		t.Errorf("Expected status 302, got %d", resp.StatusCode)
	}
}

// TestHTTP_Timeout tests request timeout
func TestHTTP_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink := NewHTTPWithOptions(100*time.Millisecond, true)
	_, err := sink.Fetch(server.URL)
	if err == nil {
		t.Error("Expected timeout error")
	}
}

// TestHTTP_Close tests that close is a no-op
func TestHTTP_Close(t *testing.T) {
	sink := NewHTTP()
	err := sink.Close()
	if err != nil {
		t.Errorf("Expected no error from Close, got: %v", err)
	}
}

// TestHTTPResponse tests HTTPResponse struct
func TestHTTPResponse(t *testing.T) {
	resp := HTTPResponse{
		StatusCode: 200,
		Body:       "test body",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected StatusCode 200, got %d", resp.StatusCode)
	}
	if resp.Body != "test body" {
		t.Errorf("Expected Body 'test body', got '%s'", resp.Body)
	}
	if resp.Headers["Content-Type"] != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", resp.Headers["Content-Type"])
	}
}

// TestHTTPOptions tests HTTPOptions struct
func TestHTTPOptions(t *testing.T) {
	opts := HTTPOptions{
		Method:          "POST",
		Headers:         map[string]string{"X-Test": "value"},
		Body:            "test body",
		FollowRedirects: true,
		Timeout:         30,
	}

	if opts.Method != "POST" {
		t.Errorf("Expected Method 'POST', got '%s'", opts.Method)
	}
	if !opts.FollowRedirects {
		t.Error("Expected FollowRedirects true")
	}
	if opts.Timeout != 30 {
		t.Errorf("Expected Timeout 30, got %d", opts.Timeout)
	}
}

// TestHTTP_Error404 tests handling of 404 response
func TestHTTP_Error404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer server.Close()

	sink := NewHTTP()
	resp, err := sink.Fetch(server.URL)

	// Should not error, just return the response
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if resp.StatusCode != 404 {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

// TestHTTP_Error500 tests handling of 500 response
func TestHTTP_Error500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	sink := NewHTTP()
	resp, err := sink.Fetch(server.URL)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if resp.StatusCode != 500 {
		t.Errorf("Expected status 500, got %d", resp.StatusCode)
	}
}
