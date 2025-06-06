package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// service address
const addr = ":6000"

var (
	apiKey    string
	caSignURL string
	devices   = make(map[string]string)
	devicesMu sync.Mutex
)

func main() {
	apiKey = os.Getenv("DEVICE_API_KEY")
	if apiKey == "" {
		log.Fatal("DEVICE_API_KEY environment variable is required")
	}
	caSignURL = os.Getenv("CA_SIGN_URL")
	if caSignURL == "" {
		caSignURL = "http://localhost:5000/sign"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/devices", auth(provisionHandler))

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	log.Printf("Device Provisioning Service started on %s", addr)
	log.Fatal(server.ListenAndServe())
}

// auth enforces X-API-Key header
func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != apiKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// provisionHandler processes a CSR and returns a device certificate chain
func provisionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		http.Error(w, "invalid CSR encoding", http.StatusBadRequest)
		return
	}
	// TODO PQC: For the issued certificate to be fully PQC,
	// the incoming CSR (csrDER) must contain a Dilithium2 public key
	// and be signed by the corresponding Dilithium2 private key from the device.
	// This service only forwards the CSR; the PQC key generation must happen on the device.
	var pemBuf bytes.Buffer
	pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// BEGIN MODIFICATION: Configure HTTP client to trust PQC CA
	caCertPath := os.Getenv("CA_CERT_FILE")
	if caCertPath == "" {
		caCertPath = "ca-cert.pem" // Default path
	}
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Printf("Error reading CA cert file %s: %v", caCertPath, err)
		http.Error(w, "internal configuration error (CA cert)", http.StatusInternalServerError)
		return
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		log.Printf("Error adding CA cert from %s to pool", caCertPath)
		http.Error(w, "internal configuration error (CA cert pool)", http.StatusInternalServerError)
		return
	}
	tlsConfig := &tls.Config{
		RootCAs: pool,
		// Add MinVersion and CurvePreferences if desired for client-side hardening
		// MinVersion: tls.VersionTLS12,
		// CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	// END MODIFICATION

	resp, err := client.Post(caSignURL, "application/x-pem-file", &pemBuf)
	if err != nil {
		http.Error(w, "failed to call CA service", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		http.Error(w, fmt.Sprintf("CA error: %s", string(body)), http.StatusBadGateway)
		return
	}
	certChain, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed to read CA response", http.StatusInternalServerError)
		return
	}
	deviceID, err := generateNonce()
	if err != nil {
		http.Error(w, "failed to generate device ID", http.StatusInternalServerError)
		return
	}
	devicesMu.Lock()
	devices[deviceID] = string(certChain)
	devicesMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"deviceID":     deviceID,
		"certChainPEM": string(certChain),
	})
}

// generateNonce returns a URL-safe base64 random string
func generateNonce() (string, error) {
	const size = 16
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
