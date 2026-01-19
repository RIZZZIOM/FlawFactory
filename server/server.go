package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/RIZZZIOM/FlawFactory/config"
	"github.com/RIZZZIOM/FlawFactory/logger"
)

// Server wraps an HTTP server with our configuration
type Server struct {
	httpServer *http.Server
	router     *Router
	logger     *logger.Logger
	tlsConfig  *config.TLSConfig
}

// New creates a new server instance with optional JSON logging
// If logFilePath is empty, no JSON logging will be performed
// host specifies the interface to bind to (e.g., "127.0.0.1" for localhost only, "0.0.0.0" for all interfaces)
func New(host string, port int, logFilePath string, tlsConfig *config.TLSConfig) (*Server, error) {
	var jsonLogger *logger.Logger
	var err error

	if logFilePath != "" {
		jsonLogger, err = logger.New(logFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize logger: %w", err)
		}
		log.Printf("Request logs will be saved to: %s", logFilePath)
	}

	router := NewRouter(jsonLogger)

	return &Server{
		httpServer: &http.Server{
			Addr:         fmt.Sprintf("%s:%d", host, port),
			Handler:      router,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		router:    router,
		logger:    jsonLogger,
		tlsConfig: tlsConfig,
	}, nil
}

// Router returns the server's router
func (s *Server) Router() *Router {
	return s.router
}

// Start begins listening for HTTP or HTTPS requests based on TLS configuration
func (s *Server) Start() error {
	if s.tlsConfig != nil && s.tlsConfig.Enabled {
		return s.startTLS()
	}
	return s.startHTTP()
}

// startHTTP starts the server in HTTP mode
func (s *Server) startHTTP() error {
	log.Printf("FlawFactory starting on http://%s", s.httpServer.Addr)

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// startTLS starts the server in HTTPS mode
func (s *Server) startTLS() error {
	certFile := s.tlsConfig.CertFile
	keyFile := s.tlsConfig.KeyFile

	// Auto-generate self-signed certificate if requested
	if s.tlsConfig.AutoGenerate {
		var err error
		certFile, keyFile, err = s.generateSelfSignedCert()
		if err != nil {
			return fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}
		log.Printf("Generated self-signed certificate: %s, %s", certFile, keyFile)
	}

	// Validate that certificate files exist
	if certFile == "" || keyFile == "" {
		return fmt.Errorf("TLS is enabled but cert_file and key_file are not specified (set auto_generate: true for self-signed certificates)")
	}

	log.Printf("FlawFactory starting on https://%s", s.httpServer.Addr)

	if err := s.httpServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// generateSelfSignedCert creates a self-signed certificate and returns the paths
func (s *Server) generateSelfSignedCert() (certFile, keyFile string, err error) {
	// Create certs directory if it doesn't exist
	certsDir := "certs"
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create certs directory: %w", err)
	}

	certFile = filepath.Join(certsDir, "server.crt")
	keyFile = filepath.Join(certsDir, "server.key")

	// Check if certificates already exist
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			log.Printf("Using existing self-signed certificates from %s", certsDir)
			return certFile, keyFile, nil
		}
	}

	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"FlawFactory"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certOut, err := os.Create(certFile)
	if err != nil {
		return "", "", fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return "", "", fmt.Errorf("failed to write cert: %w", err)
	}

	// Write private key to file
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return "", "", fmt.Errorf("failed to write key: %w", err)
	}

	log.Printf("Created new self-signed certificate in %s", certsDir)
	return certFile, keyFile, nil
}

// Stop gracefully shuts down the server
func (s *Server) Stop(ctx context.Context) error {
	log.Println("Shutting down server...")

	// Close the JSON logger if it exists
	if s.logger != nil {
		if err := s.logger.Close(); err != nil {
			log.Printf("Warning: failed to close logger: %v", err)
		}
	}

	// Shutdown gracefully waits for existing connections to finish
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown error: %w", err)
	}

	log.Println("Server stopped")
	return nil
}
