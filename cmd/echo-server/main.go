// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var (
	logBody         = flag.Bool("log-body", false, "Should the request body be logged")
	tlsCertFile     = flag.String("tls-cert-file", "", "Path to TLS certificate file (required for HTTPS)")
	tlsKeyFile      = flag.String("tls-key-file", "", "Path to TLS private key file (required for HTTPS)")
	tlsClientCAFile = flag.String("tls-client-ca-file", "", "Path to TLS CA certificate file for client certificate verification (enables mTLS)")
	healthPort      = flag.Int("health-port", 8080, "Port for HTTP health endpoint")
)

func main() {
	port := flag.Int("port", 8000, "Port to listen on")
	flag.Parse()

	// Start health server in a goroutine
	healthSrv := &http.Server{
		Handler:           http.HandlerFunc(healthHandler),
		Addr:              ":" + fmt.Sprint(*healthPort),
		WriteTimeout:      15 * time.Second,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 15 * time.Second,
	}

	go func() {
		log.Printf("Starting HTTP health server on port %d", *healthPort)
		if err := healthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Health server failed: %v", err)
		}
	}()

	// Main server for audit endpoints
	srv := &http.Server{
		Handler:           http.HandlerFunc(auditHandler),
		Addr:              ":" + fmt.Sprint(*port),
		WriteTimeout:      15 * time.Second,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 15 * time.Second,
	}

	if *tlsCertFile != "" && *tlsKeyFile != "" {
		tlsConfig, err := setupTLSConfig(*tlsCertFile, *tlsKeyFile, *tlsClientCAFile)
		if err != nil {
			log.Fatalf("Failed to setup TLS configuration: %v", err)
		}
		srv.TLSConfig = tlsConfig

		if *tlsClientCAFile != "" {
			log.Printf("Starting HTTPS echo server with mTLS on port %d", *port)
		} else {
			log.Printf("Starting HTTPS echo server on port %d", *port)
		}
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}

	log.Printf("Starting HTTP echo server on port %d", *port)
	log.Fatal(srv.ListenAndServe())
}

// setupTLSConfig creates a TLS configuration with optional client certificate verification
func setupTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate and key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	// If CA file is provided, enable client certificate verification
	if caFile != "" {
		caCert, err := os.ReadFile(filepath.Clean(caFile))
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		log.Printf("Client certificate verification enabled using CA: %s", caFile)
	}

	return tlsConfig, nil
}

// healthHandler handles only health check requests on HTTP
func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		w.Header().Add("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"status": "ok"}`))
		if err != nil {
			log.Print(err)
		}
		return
	}

	// For non-health paths, return 404
	http.NotFound(w, r)
}

// auditHandler handles audit requests (renamed from genericHandler)
func auditHandler(w http.ResponseWriter, r *http.Request) {
	// Log client certificate information if present
	var clientCertInfo string
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		clientCertInfo = fmt.Sprintf(" [Client: %s, Issuer: %s]", cert.Subject.CommonName, cert.Issuer.CommonName)
	}

	if r.Method == http.MethodPost {
		defer func() {
			if err := r.Body.Close(); err != nil {
				log.Printf("Error closing body: %s\n", err)
			}
		}()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Add("Content-Type", "application/json")
			http.Error(w, `{"success": false}`, http.StatusInternalServerError)
			return
		}
		if *logBody {
			log.Printf("Method: %s, Path: %s%s, Body: %s", r.Method, r.URL.Path, clientCertInfo, string(body))
		} else {
			log.Printf("Method: %s, Path: %s%s", r.Method, r.URL.Path, clientCertInfo)
		}
	} else {
		log.Printf("Method: %s, Path: %s%s", r.Method, r.URL.Path, clientCertInfo)
	}

	w.Header().Add("Content-Type", "application/json")
	_, err := w.Write([]byte(`{"success": true}`))
	if err != nil {
		log.Print(err)
	}
}
