package main

import (
   "context"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
   "crypto/sha256"
   "database/sql"
   "encoding/base64"
   "encoding/hex"
   "encoding/json"
   "fmt"
   "log"
   "net/http"
   "os"
   "os/signal"
   "strings"
   "syscall"
   "time"
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

// SignRequest defines a code-signing request
type SignRequest struct {
   ArtifactHash string `json:"artifactHash"`
   Algorithm    string `json:"algorithm"`
}

// SignResponse returns the hybrid signature and log URL
type SignResponse struct {
   Signature   string `json:"signature"`
   LogEntryURL string `json:"logEntryURL"`
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
   addr       = getEnv("SIGNING_ADDR", ":7000")
   dbDSN      = getEnv("DB_DSN", "signing.db")
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
  timestamp DATETIME NOT NULL,
  FOREIGN KEY(account_id) REFERENCES accounts(id)
);`,
   }
   for _, m := range migrations {
       if _, err := db.Exec(m); err != nil {
           log.Fatalf("migration failed: %v", err)
       }
   }

   // generate signing keys
   privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
   if err != nil {
       log.Fatalf("failed to generate ECDSA key: %v", err)
   }
   _, pqPrivLocal, err := dilithium2.GenerateKey(rand.Reader)
   if err != nil {
       log.Fatalf("failed to generate PQC key: %v", err)
   }
   pqPriv = pqPrivLocal

   // HTTP server setup
   mux := http.NewServeMux()
   // public endpoints
   mux.HandleFunc("/v1/accounts", accountsHandler)
   mux.HandleFunc("/v1/log/", logHandler)
   mux.HandleFunc("/v1/log", listHandler)
   mux.Handle("/metrics", promhttp.Handler())
   // protected endpoints
   mux.Handle("/v1/accounts/", clientAuth(http.HandlerFunc(accountInfoHandler)))
   mux.Handle("/v1/signatures", clientAuth(http.HandlerFunc(signHandler)))

   srv := &http.Server{Addr: addr, Handler: mux}
   go func() {
       log.Printf("Service listening on %s", addr)
       if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
       `INSERT INTO log_entries(id,account_id,artifact_hash,algorithm,signature,timestamp) VALUES(?,?,?,?,?,?);`,
       entryID, accountID, req.ArtifactHash, req.Algorithm, hybridSig, ts,
   )
   if err != nil {
       http.Error(w, "failed to record log entry", http.StatusInternalServerError)
       return
   }
   resp := SignResponse{Signature: hybridSig, LogEntryURL: fmt.Sprintf("http://%s/v1/log/%s", r.Host, entryID)}
   w.Header().Set("Content-Type", "application/json")
   json.NewEncoder(w).Encode(resp)
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