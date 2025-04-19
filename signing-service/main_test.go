package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	eddilithium2 "github.com/cloudflare/circl/sign/eddilithium2"
	_ "github.com/mattn/go-sqlite3"
)

// init sets up an in-memory DB and keys
func init() {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(fmt.Sprintf("failed to open in-memory DB: %v", err))
	}
	// migrate schema
	schemas := []string{
		`CREATE TABLE accounts (id TEXT PRIMARY KEY, api_key TEXT UNIQUE NOT NULL, plan TEXT NOT NULL, usage_count INTEGER NOT NULL, usage_reset DATETIME NOT NULL);`,
		`CREATE TABLE log_entries (id TEXT PRIMARY KEY, account_id TEXT NOT NULL, artifact_hash TEXT NOT NULL, algorithm TEXT NOT NULL, signature TEXT NOT NULL, sbom TEXT, provenance TEXT, timestamp DATETIME NOT NULL, FOREIGN KEY(account_id) REFERENCES accounts(id));`,
	}
	for _, s := range schemas {
		if _, err := db.Exec(s); err != nil {
			panic(fmt.Sprintf("migration failed: %v", err))
		}
	}
	// generate keys
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate ECDSA key: %v", err))
	}
	_, pqPrivLocal, err := eddilithium2.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate PQC key: %v", err))
	}
	pqPriv = pqPrivLocal
}

// TestAccountAndSignFlow covers account creation, usage, signing, and log retrieval
func TestAccountAndSignFlow(t *testing.T) {
	// setup HTTP handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/accounts", accountsHandler) // No auth required for account creation
	mux.Handle("/v1/accounts/", clientAuth(http.HandlerFunc(accountInfoHandler)))
	mux.Handle("/v1/signatures", clientAuth(http.HandlerFunc(signHandler)))
	mux.Handle("/v1/log/", clientAuth(http.HandlerFunc(logHandler)))

	server := httptest.NewServer(mux)
	defer server.Close()

	// 1. Create account
	resp, err := http.Post(server.URL+"/v1/accounts", "application/json", nil)
	if err != nil {
		t.Fatalf("account creation request failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", resp.StatusCode)
	}
	var accResp struct {
		AccountID  string `json:"accountID"`
		APIKey     string `json:"apiKey"`
		Plan       string `json:"plan"`
		UsageLimit int    `json:"usageLimit"`
		UsageCount int    `json:"usageCount"`
		UsageReset string `json:"usageReset"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&accResp); err != nil {
		t.Fatalf("invalid account response: %v", err)
	}
	apiKey := accResp.APIKey
	accountID := accResp.AccountID

	// 2. Check account info
	req, _ := http.NewRequest("GET", server.URL+"/v1/accounts/"+accountID, nil)
	req.Header.Set("X-API-Key", apiKey)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("account info request failed: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for account info, got %d", resp2.StatusCode)
	}

	// 3. Sign an artifact
	data := []byte("hello world")
	hash := sha256.Sum256(data)
	hashStr := fmt.Sprintf("sha256:%x", hash[:])
	signReq := map[string]string{"artifactHash": hashStr, "algorithm": "ECDSA+Dilithium2"}
	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(signReq)
	req3, _ := http.NewRequest("POST", server.URL+"/v1/signatures", buf)
	req3.Header.Set("X-API-Key", apiKey)
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("sign request failed: %v", err)
	}
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for sign, got %d", resp3.StatusCode)
	}
	var signResp SignResponse
	if err := json.NewDecoder(resp3.Body).Decode(&signResp); err != nil {
		t.Fatalf("invalid sign response: %v", err)
	}
	if !strings.HasPrefix(signResp.Signature, "ecdsa:") || !strings.Contains(signResp.Signature, "pqc:") {
		t.Errorf("unexpected signature format: %s", signResp.Signature)
	}

	// 4. Retrieve log entry
	logURL := strings.Replace(signResp.LogEntryURL, "https://", "http://", 1)
	req4, _ := http.NewRequest("GET", logURL, nil)
	req4.Header.Set("X-API-Key", apiKey)
	resp4, err := http.DefaultClient.Do(req4)
	if err != nil {
		t.Fatalf("log entry request failed: %v", err)
	}
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for log entry, got %d", resp4.StatusCode)
	}
	var entry LogEntry
	if err := json.NewDecoder(resp4.Body).Decode(&entry); err != nil {
		t.Fatalf("invalid log entry: %v", err)
	}
	if entry.ArtifactHash != hashStr {
		t.Errorf("artifact hash mismatch: got %s, want %s", entry.ArtifactHash, hashStr)
	}
}
