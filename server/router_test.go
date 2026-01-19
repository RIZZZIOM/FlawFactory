package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNewRouter tests router creation
func TestNewRouter(t *testing.T) {
	router := NewRouter(nil)
	if router == nil {
		t.Fatal("Expected router to be created, got nil")
	}
	if router.mux == nil {
		t.Fatal("Expected mux to be initialized, got nil")
	}
}

// TestRouter_HandleFunc tests registering a handler
func TestRouter_HandleFunc(t *testing.T) {
	router := NewRouter(nil)

	// Register a test handler
	called := false
	router.HandleFunc("GET", "/test", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Create a test request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	// Serve the request
	router.ServeHTTP(w, req)

	// Verify handler was called
	if !called {
		t.Error("Expected handler to be called")
	}

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if body != "test response" {
		t.Errorf("Expected body 'test response', got '%s'", body)
	}
}

// TestRouter_MultipleRoutes tests multiple route registration
func TestRouter_MultipleRoutes(t *testing.T) {
	router := NewRouter(nil)

	// Register multiple routes
	router.HandleFunc("GET", "/users", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("users"))
	})

	router.HandleFunc("GET", "/posts", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("posts"))
	})

	router.HandleFunc("POST", "/users", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("create user"))
	})

	// Test each route
	tests := []struct {
		method       string
		path         string
		expectedBody string
	}{
		{"GET", "/users", "users"},
		{"GET", "/posts", "posts"},
		{"POST", "/users", "create user"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			body := w.Body.String()
			if body != tt.expectedBody {
				t.Errorf("Expected body '%s', got '%s'", tt.expectedBody, body)
			}
		})
	}
}

// TestRouter_404 tests handling of unregistered routes
func TestRouter_404(t *testing.T) {
	router := NewRouter(nil)

	router.HandleFunc("GET", "/exists", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("found"))
	})

	req := httptest.NewRequest("GET", "/notfound", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

// TestRouter_MethodNotAllowed tests wrong HTTP method
func TestRouter_MethodNotAllowed(t *testing.T) {
	router := NewRouter(nil)

	router.HandleFunc("GET", "/resource", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("get"))
	})

	// Try POST on a GET-only route
	req := httptest.NewRequest("POST", "/resource", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Go 1.22+ returns 405 Method Not Allowed
	if w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusNotFound {
		t.Errorf("Expected status 405 or 404, got %d", w.Code)
	}
}

// TestRouter_StatusCodeCapture tests that responseWriter captures status codes
func TestRouter_StatusCodeCapture(t *testing.T) {
	router := NewRouter(nil)

	router.HandleFunc("GET", "/error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	req := httptest.NewRequest("GET", "/error", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

// TestRouter_Headers tests setting response headers
func TestRouter_Headers(t *testing.T) {
	router := NewRouter(nil)

	router.HandleFunc("GET", "/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	req := httptest.NewRequest("GET", "/json", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}
}

// TestRouter_RequestData tests accessing request data
func TestRouter_RequestData(t *testing.T) {
	router := NewRouter(nil)

	router.HandleFunc("GET", "/echo", func(w http.ResponseWriter, r *http.Request) {
		// Echo query parameter
		query := r.URL.Query().Get("message")
		w.Write([]byte(query))
	})

	req := httptest.NewRequest("GET", "/echo?message=hello", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	body := w.Body.String()
	if body != "hello" {
		t.Errorf("Expected body 'hello', got '%s'", body)
	}
}

// TestResponseWriter_WriteHeader tests status code capturing
func TestResponseWriter_WriteHeader(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	rw.WriteHeader(http.StatusCreated)

	if rw.statusCode != http.StatusCreated {
		t.Errorf("Expected status code 201, got %d", rw.statusCode)
	}

	if w.Code != http.StatusCreated {
		t.Errorf("Expected underlying writer status 201, got %d", w.Code)
	}
}

// TestResponseWriter_DefaultStatusCode tests default status code
func TestResponseWriter_DefaultStatusCode(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	// Write without calling WriteHeader (should default to 200)
	rw.Write([]byte("test"))

	if rw.statusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", rw.statusCode)
	}
}
