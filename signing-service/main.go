package main

import (
   "bytes"
   "context"
   "crypto"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
   "crypto/sha256"
   "crypto/tls"
   "crypto/x509"
   "database/sql"
   "encoding/base64"
   "encoding/hex"
   "encoding/json"
   "encoding/pem"
   "fmt"
   "io"
   "io/ioutil"
   "log"
   "net/http"
   "os"
   "os/signal"
   "path/filepath"
   "strings"
   "syscall"
   "time"
   "math/big"

   "github.com/ThalesIgnite/crypto11"
   _ "github.com/mattn/go-sqlite3"
   "github.com/cloudflare/circl/sign/dilithium2"
   "github.com/prometheus/client_golang/prometheus/promhttp"
   "golang.org/x/crypto/ocsp"
)
   _ "github.com/mattn/go-sqlite3"
   "github.com/cloudflare/circl/sign/dilithium2"
   "github.com/prometheus/client_golang/prometheus/promhttp"
)

// Free tier limit per month
const FreeLimit = 1000

// contextKey is type for context keys
type contextKey string

const ctxKeyAccountID contextKey = "accountID"

// Account represents a user account with usage tracking
type Account struct {
   ID         string
   Plan       string
   UsageCount int
   UsageReset time.Time
}

// sbomHandler returns the SBOM for a log entry
func sbomHandler(w http.ResponseWriter, r *http.Request, id string) {
   row := db.QueryRow(`SELECT sbom FROM log_entries WHERE id = ?`, id)
   var sbom string
   if err := row.Scan(&sbom); err != nil || sbom == "" {
       http.Error(w, "SBOM not found", http.StatusNotFound)
       return
   }
   w.Header().Set("Content-Type", "application/json")
   w.Write([]byte(sbom))
}

// provenanceHandler returns the provenance for a log entry
func provenanceHandler(w http.ResponseWriter, r *http.Request, id string) {
   row := db.QueryRow(`SELECT provenance FROM log_entries WHERE id = ?`, id)
   var prov string
   if err := row.Scan(&prov); err != nil || prov == "" {
       http.Error(w, "provenance not found", http.StatusNotFound)
       return
   }
   w.Header().Set("Content-Type", "application/json")
   w.Write([]byte(prov))
}

// SignRequest defines a code-signing request
type SignRequest struct {
   ArtifactHash string `json:"artifactHash"`
   Algorithm    string `json:"algorithm"`
   SBOM         string `json:"sbom,omitempty"`
   Provenance   string `json:"provenance,omitempty"`
}

// SignResponse returns the hybrid signature and log URL
type SignResponse struct {
   Signature      string `json:"signature"`
   LogEntryURL    string `json:"logEntryURL"`
   SBOMURL        string `json:"sbomURL,omitempty"`
   ProvenanceURL  string `json:"provenanceURL,omitempty"`
}

// LogEntry is a transparency log record
type LogEntry struct {
   ID           string    `json:"id"`
   AccountID    string    `json:"accountID"`
   ArtifactHash string    `json:"artifactHash"`
   Algorithm    string    `json:"algorithm"`
   Signature    string    `json:"signature"`
   Timestamp    time.Time `json:"timestamp"`
}

// Configuration and global variables
var (
   // service configuration
   addr        = getEnv("SIGNING_ADDR", ":7000")
   dbDSN       = getEnv("DB_DSN", "signing.db")
   keyDir      = getEnv("KEY_DIR", "keys")
   tlsCertFile = getEnv("TLS_CERT_FILE", "signing-service-cert.pem")
   tlsKeyFile  = getEnv("TLS_KEY_FILE", "signing-service-key.pem")

   // global state
   db         *sql.DB
   privateKey *ecdsa.PrivateKey
   pqPub      dilithium2.PublicKey
   pqPriv     dilithium2.PrivateKey
)

// getEnv returns the environment variable or default value
func getEnv(key, def string) string {
   if v := os.Getenv(key); v != "" {
       return v
   }
   return def
}

func main() {
   // initialize database
   var err error
   db, err = sql.Open("sqlite3", dbDSN)
   if err != nil {
       log.Fatalf("failed to open database: %v", err)
   }
   defer db.Close()

   // migrate schema
   migrations := []string{
       `CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  api_key TEXT UNIQUE NOT NULL,
  plan TEXT NOT NULL,
  usage_count INTEGER NOT NULL,
  usage_reset DATETIME NOT NULL
);`,
       `CREATE TABLE IF NOT EXISTS log_entries (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  artifact_hash TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  signature TEXT NOT NULL,
  sbom TEXT,
  provenance TEXT,
  timestamp DATETIME NOT NULL,
  FOREIGN KEY(account_id) REFERENCES accounts(id)
);`,
   }
   for _, m := range migrations {
       if _, err := db.Exec(m); err != nil {
           log.Fatalf("migration failed: %v", err)
       }
   }

   // initialize key store (FS or PKCS#11)
   storeType := getEnv("KEYSTORE_TYPE", "fs")
   var ks KeyStore
   switch storeType {
   case "fs":
       ks, err = NewFSKeyStore(keyDir)
   case "pkcs11":
       ks, err = NewPKCS11KeyStore(keyDir)
   default:
       log.Fatalf("unknown KEYSTORE_TYPE '%s', must be 'fs' or 'pkcs11'", storeType)
   }
   if err != nil {
       log.Fatalf("failed to initialize keystore: %v", err)
   }
   // load or generate ECDSA key
   rawKey, err := ks.GetPrivateKey("ecdsa")
   if err == ErrKeyNotFound {
       priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
       if err != nil {
           log.Fatalf("failed to generate ECDSA key: %v", err)
       }
       if err := ks.ImportPrivateKey("ecdsa", priv); err != nil {
           log.Fatalf("failed to store ECDSA key: %v", err)
       }
       privateKey = priv
   } else if err != nil {
       log.Fatalf("error loading ECDSA key: %v", err)
   } else {
       priv, ok := rawKey.(*ecdsa.PrivateKey)
       if !ok {
           log.Fatalf("invalid ECDSA key type")
       }
       privateKey = priv
   }
   // load or generate PQC Dilithium2 key
   pqcPath := filepath.Join(keyDir, "pqc-key.bin")
   if data, err := ioutil.ReadFile(pqcPath); err == nil {
       var priv dilithium2.PrivateKey
       if err := priv.UnmarshalBinary(data); err != nil {
           log.Fatalf("failed to parse PQC key: %v", err)
       }
       pqPriv = priv
       pqPub = priv.Public().(dilithium2.PublicKey)
   } else {
       pub, priv, err := dilithium2.GenerateKey(rand.Reader)
       if err != nil {
           log.Fatalf("failed to generate PQC key: %v", err)
       }
       data, err := priv.MarshalBinary()
       if err != nil {
           log.Fatalf("failed to marshal PQC key: %v", err)
       }
       if err := ioutil.WriteFile(pqcPath+".tmp", data, 0600); err != nil {
           log.Fatalf("failed to write PQC key: %v", err)
       }
       if err := os.Rename(pqcPath+".tmp", pqcPath); err != nil {
           log.Fatalf("failed to store PQC key: %v", err)
       }
       pqPriv = priv
       pqPub = pub
   }

   // HTTP and TLS server setup
   // HTTP and TLS server setup
   mux := http.NewServeMux()
   // health & readiness probes
   mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
   mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
       // readiness: ensure DB is open and keys loaded
       if db == nil {
           http.Error(w, "db not ready", http.StatusServiceUnavailable)
           return
       }
       // optional: ping DB
       if err := db.Ping(); err != nil {
           http.Error(w, "db ping failed", http.StatusServiceUnavailable)
           return
       }
       w.WriteHeader(http.StatusOK)
   })
   // public endpoints
   mux.HandleFunc("/v1/accounts", accountsHandler)
   mux.HandleFunc("/v1/log/", logRouter)
   mux.HandleFunc("/v1/log", listHandler)
   mux.Handle("/metrics", promhttp.Handler())
   // protected endpoints
   mux.Handle("/v1/accounts/", clientAuth(http.HandlerFunc(accountInfoHandler)))
   mux.Handle("/v1/signatures", clientAuth(http.HandlerFunc(signHandler)))

   // initialize keystore for TLS identity
   tlsKeyDir := getEnv("KEY_DIR", "keys")
   ks, err := NewFSKeyStore(tlsKeyDir)
   if err != nil {
       log.Fatalf("failed to init keystore: %v", err)
   }
   // load or generate TLS private key
   rawTlsKey, err := ks.GetPrivateKey("tls")
   var tlsPriv *ecdsa.PrivateKey
   if err == ErrKeyNotFound {
       p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
       if err != nil {
           log.Fatalf("generate TLS key: %v", err)
       }
       if err := ks.ImportPrivateKey("tls", p); err != nil {
           log.Fatalf("store TLS key: %v", err)
       }
       tlsPriv = p
   } else if err != nil {
       log.Fatalf("load TLS key: %v", err)
   } else {
       var ok bool
       tlsPriv, ok = rawTlsKey.(*ecdsa.PrivateKey)
       if !ok {
           log.Fatalf("invalid TLS key type")
       }
   }
   // load or request TLS certificate from CA
   certObj, err := ks.GetCertificate("tls")
   if err == ErrKeyNotFound {
       csrTmpl := x509.CertificateRequest{Subject: pkix.Name{CommonName: "signing-service"}}
       csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTmpl, tlsPriv)
       if err != nil {
           log.Fatalf("create CSR: %v", err)
       }
       buf := &bytes.Buffer{}
       pem.Encode(buf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
       // request from CA
       caCertPEM, err := ioutil.ReadFile(getEnv("CA_CERT_FILE", "ca-cert.pem"))
       if err != nil {
           log.Fatalf("read CA cert: %v", err)
       }
       pool := x509.NewCertPool()
       if !pool.AppendCertsFromPEM(caCertPEM) {
           log.Fatalf("failed to load CA root")
       }
       client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
       resp, err := client.Post(getEnv("CA_SIGN_URL", "https://localhost:5000/sign"), "application/x-pem-file", buf)
       if err != nil {
           log.Fatalf("CSR sign request failed: %v", err)
       }
       body, err := ioutil.ReadAll(resp.Body)
       resp.Body.Close()
       if err != nil {
           log.Fatalf("read CA response: %v", err)
       }
       block, _ := pem.Decode(body)
       if block == nil || block.Type != "CERTIFICATE" {
           log.Fatalf("invalid certificate PEM from CA")
       }
       cert, err := x509.ParseCertificate(block.Bytes)
       if err != nil {
           log.Fatalf("parse certificate: %v", err)
       }
       if err := ks.ImportCertificate("tls", cert); err != nil {
           log.Fatalf("store TLS cert: %v", err)
       }
       certObj = cert
   } else if err != nil {
       log.Fatalf("load TLS cert: %v", err)
   }
   // prepare TLS certificate
   tlsCert := tls.Certificate{Certificate: [][]byte{certObj.Raw}, PrivateKey: tlsPriv}
   // initial OCSP staple
   if reqBytes, err := ocsp.CreateRequest(certObj, caCert, &ocsp.RequestOptions{Hash: crypto.SHA1}); err == nil {
       // fetch OCSP response
       caCertPEM, err := ioutil.ReadFile(getEnv("CA_CERT_FILE", "ca-cert.pem"))
       if err != nil {
           log.Printf("warning: cannot read CA cert for OCSP: %v", err)
       } else {
           poolOCSP := x509.NewCertPool()
           if !poolOCSP.AppendCertsFromPEM(caCertPEM) {
               log.Printf("warning: failed to append CA cert for OCSP")
           } else {
               client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: poolOCSP}}}
               resp, err := client.Post(getEnv("CA_OCSP_URL", "https://localhost:5000/ocsp"), "application/ocsp-request", bytes.NewReader(reqBytes))
               if err != nil {
                   log.Printf("warning: OCSP request failed: %v", err)
               } else {
                   if respBytes, err := ioutil.ReadAll(resp.Body); err == nil {
                       tlsCert.OCSPStaple = respBytes
                   }
                   resp.Body.Close()
               }
           }
       }
   }
   // start HTTPS server
   server := &http.Server{Addr: addr, Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12}}
   go func() {
       log.Printf("Signing service listening on %s (HTTPS)", addr)
       if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
           log.Fatalf("server error: %v", err)
       }
   }()

   // graceful shutdown
   quit := make(chan os.Signal, 1)
   signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
   <-quit
   log.Println("shutting down...")
   ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
   defer cancel()
   if err := srv.Shutdown(ctx); err != nil {
       log.Fatalf("shutdown error: %v", err)
   }
   log.Println("service stopped")
}

// accountsHandler registers a new free-tier account
func accountsHandler(w http.ResponseWriter, r *http.Request) {
   if r.Method != http.MethodPost {
       http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
       return
   }
   accountID := newEntryID()
   keySum := sha256.Sum256([]byte(accountID + time.Now().String()))
   apiKey := base64.RawURLEncoding.EncodeToString(keySum[:])
   now := time.Now().UTC()
   reset := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
   plan := "free"
   _, err := db.Exec(
       `INSERT INTO accounts(id,api_key,plan,usage_count,usage_reset) VALUES(?,?,?,?,?);`,
       accountID, apiKey, plan, 0, reset,
   )
   if err != nil {
       http.Error(w, fmt.Sprintf("account creation failed: %v", err), http.StatusInternalServerError)
       return
   }
   w.Header().Set("Content-Type", "application/json")
   w.WriteHeader(http.StatusCreated)
   json.NewEncoder(w).Encode(map[string]interface{}{
       "accountID":  accountID,
       "apiKey":     apiKey,
       "plan":       plan,
       "usageLimit": FreeLimit,
       "usageCount": 0,
       "usageReset": reset.Format(time.RFC3339),
   })
}

// accountInfoHandler returns usage stats for the authenticated account
func accountInfoHandler(w http.ResponseWriter, r *http.Request) {
   accID, ok := r.Context().Value(ctxKeyAccountID).(string)
   if !ok {
       http.Error(w, "unauthorized", http.StatusUnauthorized)
       return
   }
   row := db.QueryRow(
       `SELECT plan,usage_count,usage_reset FROM accounts WHERE id = ?`, accID,
   )
   var plan string
   var usageCount int
   var usageReset time.Time
   if err := row.Scan(&plan, &usageCount, &usageReset); err != nil {
       http.Error(w, "account not found", http.StatusNotFound)
       return
   }
   w.Header().Set("Content-Type", "application/json")
   json.NewEncoder(w).Encode(map[string]interface{}{
       "accountID":  accID,
       "plan":       plan,
       "usageLimit": FreeLimit,
       "usageCount": usageCount,
       "usageReset": usageReset.Format(time.RFC3339),
   })
}

// clientAuth enforces X-API-Key and usage limits
func clientAuth(next http.Handler) http.Handler {
   return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
       key := r.Header.Get("X-API-Key")
       if key == "" {
           http.Error(w, "unauthorized", http.StatusUnauthorized)
           return
       }
       row := db.QueryRow(
           `SELECT id,plan,usage_count,usage_reset FROM accounts WHERE api_key = ?`, key,
       )
       var acc Account
       var usageReset time.Time
       if err := row.Scan(&acc.ID, &acc.Plan, &acc.UsageCount, &usageReset); err != nil {
           http.Error(w, "unauthorized", http.StatusUnauthorized)
           return
       }
       now := time.Now().UTC()
       if now.After(usageReset) {
           acc.UsageCount = 0
           usageReset = time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
           db.Exec(`UPDATE accounts SET usage_count=?,usage_reset=? WHERE id=?`, 0, usageReset, acc.ID)
       }
       if acc.Plan == "free" && acc.UsageCount >= FreeLimit {
           http.Error(w, "free tier limit exceeded", http.StatusPaymentRequired)
           return
       }
       acc.UsageCount++
       db.Exec(`UPDATE accounts SET usage_count=? WHERE id=?`, acc.UsageCount, acc.ID)
       ctx := context.WithValue(r.Context(), ctxKeyAccountID, acc.ID)
       next.ServeHTTP(w, r.WithContext(ctx))
   })
}

// signHandler processes hybrid signing requests
func signHandler(w http.ResponseWriter, r *http.Request) {
   if r.Method != http.MethodPost {
       http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
       return
   }
   var req SignRequest
   if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
       http.Error(w, "invalid JSON payload", http.StatusBadRequest)
       return
   }
   parts := strings.SplitN(req.ArtifactHash, ":", 2)
   if len(parts) != 2 || parts[0] != "sha256" {
       http.Error(w, "invalid hash format", http.StatusBadRequest)
       return
   }
   hashBytes, err := hex.DecodeString(parts[1])
   if err != nil {
       http.Error(w, "invalid hash hex", http.StatusBadRequest)
       return
   }
   sigBytes, err := ecdsa.SignASN1(rand.Reader, privateKey, hashBytes)
   if err != nil {
       http.Error(w, "ECDSA signing error", http.StatusInternalServerError)
       return
   }
   sigECDSA := base64.RawURLEncoding.EncodeToString(sigBytes)
   sigPQC := base64.RawURLEncoding.EncodeToString(pqPriv.Sign(rand.Reader, hashBytes))
   hybridSig := fmt.Sprintf("ecdsa:%s;pqc:%s", sigECDSA, sigPQC)
   entryID := newEntryID()
   accountID := r.Context().Value(ctxKeyAccountID).(string)
   ts := time.Now().UTC()
   _, err = db.Exec(
       `INSERT INTO log_entries(id,account_id,artifact_hash,algorithm,signature,sbom,provenance,timestamp) VALUES(?,?,?,?,?,?,?,?);`,
       entryID, accountID, req.ArtifactHash, req.Algorithm, hybridSig, req.SBOM, req.Provenance, ts,
   )
   if err != nil {
       http.Error(w, "failed to record log entry", http.StatusInternalServerError)
       return
   }
   resp := SignResponse{Signature: hybridSig, LogEntryURL: fmt.Sprintf("http://%s/v1/log/%s", r.Host, entryID)}
   w.Header().Set("Content-Type", "application/json")
   json.NewEncoder(w).Encode(resp)
}

// logRouter routes log entry, sbom, and provenance requests
func logRouter(w http.ResponseWriter, r *http.Request) {
   path := strings.TrimPrefix(r.URL.Path, "/v1/log/")
   if strings.HasSuffix(path, "/sbom") {
       id := strings.TrimSuffix(path, "/sbom")
       sbomHandler(w, r, id)
       return
   }
   if strings.HasSuffix(path, "/provenance") {
       id := strings.TrimSuffix(path, "/provenance")
       provenanceHandler(w, r, id)
       return
   }
   logHandler(w, r)
}

// logHandler retrieves a log entry by ID
func logHandler(w http.ResponseWriter, r *http.Request) {
   id := strings.TrimPrefix(r.URL.Path, "/v1/log/")
   row := db.QueryRow(`SELECT id,account_id,artifact_hash,algorithm,signature,timestamp FROM log_entries WHERE id=?`, id)
   var e LogEntry
   if err := row.Scan(&e.ID, &e.AccountID, &e.ArtifactHash, &e.Algorithm, &e.Signature, &e.Timestamp); err != nil {
       http.Error(w, "not found", http.StatusNotFound)
       return
   }
   w.Header().Set("Content-Type", "application/json")
   json.NewEncoder(w).Encode(e)
}

// listHandler lists log entries (public) with limit/offset
func listHandler(w http.ResponseWriter, r *http.Request) {
   limit := r.URL.Query().Get("limit")
   offset := r.URL.Query().Get("offset")
   if limit == "" {
       limit = "10"
   }
   if offset == "" {
       offset = "0"
   }
   query := fmt.Sprintf(
       "SELECT id,account_id,artifact_hash,algorithm,signature,timestamp FROM log_entries ORDER BY timestamp DESC LIMIT %s OFFSET %s", limit, offset,
   )
   rows, err := db.Query(query)
   if err != nil {
       http.Error(w, "query error", http.StatusInternalServerError)
       return
   }
   defer rows.Close()
   var entries []LogEntry
   for rows.Next() {
       var e LogEntry
       if err := rows.Scan(&e.ID, &e.AccountID, &e.ArtifactHash, &e.Algorithm, &e.Signature, &e.Timestamp); err != nil {
           http.Error(w, "scan error", http.StatusInternalServerError)
           return
       }
       entries = append(entries, e)
   }
   w.Header().Set("Content-Type", "application/json")
   json.NewEncoder(w).Encode(entries)
}

// newEntryID generates a URL-safe random ID
func newEntryID() string {
   b := make([]byte, 8)
   if _, err := rand.Read(b); err != nil {
       return fmt.Sprint(time.Now().UnixNano())
   }
   return base64.RawURLEncoding.EncodeToString(b)
}