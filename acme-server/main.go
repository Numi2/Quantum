package main

import (
   "bytes"
   "crypto/rand"
   "encoding/base64"
   "encoding/json"
   "encoding/pem"
   "io"
   "log"
   "net/http"
   "strings"
)

const addr = ":4000"

// Directory describes ACME endpoint URLs
type Directory struct {
   NewNonce   string `json:"newNonce"`
   NewAccount string `json:"newAccount"`
   NewOrder   string `json:"newOrder"`
   RevokeCert string `json:"revokeCert"`
   KeyChange  string `json:"keyChange"`
}

var dir = Directory{
   NewNonce:   "http://localhost" + addr + "/acme/new-nonce",
   NewAccount: "http://localhost" + addr + "/acme/new-account",
   NewOrder:   "http://localhost" + addr + "/acme/new-order",
   RevokeCert: "http://localhost" + addr + "/acme/revoke-cert",
   KeyChange:  "http://localhost" + addr + "/acme/key-change",
}

func main() {
   http.HandleFunc("/directory", directoryHandler)
   http.HandleFunc("/acme/new-nonce", newNonceHandler)
   http.HandleFunc("/acme/new-account", newAccountHandler)
   http.HandleFunc("/acme/new-order", newOrderHandler)
   http.HandleFunc("/acme/challenge/", challengeHandler)
   http.HandleFunc("/acme/finalize/", finalizeHandler)
   http.HandleFunc("/acme/cert/", certHandler)
   http.HandleFunc("/acme/revoke-cert", stubHandler)
   http.HandleFunc("/acme/key-change", stubHandler)

   log.Printf("ACME server starting on %s", addr)
   log.Fatal(http.ListenAndServe(addr, nil))
}

// directoryHandler returns the ACME directory
func directoryHandler(w http.ResponseWriter, r *http.Request) {
   w.Header().Set("Content-Type", "application/json")
   if err := json.NewEncoder(w).Encode(dir); err != nil {
       http.Error(w, "failed to encode directory", http.StatusInternalServerError)
   }
}

// newNonceHandler returns a Replay-Nonce header
func newNonceHandler(w http.ResponseWriter, r *http.Request) {
   nonce, err := generateNonce()
   if err != nil {
       http.Error(w, "unable to generate nonce", http.StatusInternalServerError)
       return
   }
   w.Header().Set("Replay-Nonce", nonce)
   w.WriteHeader(http.StatusOK)
}

// stubHandler is a placeholder for unimplemented ACME endpoints
func stubHandler(w http.ResponseWriter, r *http.Request) {
   http.Error(w, "not implemented", http.StatusNotImplemented)
}

// generateNonce creates a URL-safe base64-encoded random string
func generateNonce() (string, error) {
   const size = 16
   b := make([]byte, size)
   if _, err := rand.Read(b); err != nil {
       return "", err
   }
   return base64.RawURLEncoding.EncodeToString(b), nil
}

// In-memory stores
var (
   accounts    = make(map[string]Account)
   orders      = make(map[string]Order)
   challenges  = make(map[string]Challenge)
   orderTokens = make(map[string]string)
)

// Account represents a registered ACME account
type Account struct {
   Status string `json:"status"`
}

// Order tracks ACME order state and certificate chain
type Order struct {
   Status    string
   CertURL   string
   CertChain []byte
}

// Challenge holds HTTP-01 challenge data
type Challenge struct {
   Token           string `json:"token"`
   KeyAuthorization string `json:"keyAuthorization"`
   Status          string `json:"status"`
}

// newAccountHandler registers a new ACME account (expects JWS)
func newAccountHandler(w http.ResponseWriter, r *http.Request) {
   // verify JWS and extract account public key
   payload, _, jwk, err := verifyJWS(w, r)
   if err != nil {
       return
   }
   // payload may contain termsOfServiceAgreed etc; ignore for now
   _ = payload
   // generate account ID
   id, err := generateNonce()
   if err != nil {
       http.Error(w, "unable to generate account ID", http.StatusInternalServerError)
       return
   }
   accountURL := fmt.Sprintf("http://%s/acme/acct/%s", r.Host, id)
   // store account
   accounts[accountURL] = Account{Status: "valid", Key: *jwk}
   w.Header().Set("Location", accountURL)
   w.WriteHeader(http.StatusCreated)
   json.NewEncoder(w).Encode(map[string]string{"status": "valid"})
}

// newOrderHandler creates a new order (expects JWS)
func newOrderHandler(w http.ResponseWriter, r *http.Request) {
   // verify JWS and extract payload
   payload, accountURL, _, err := verifyJWS(w, r)
   if err != nil {
       return
   }
   // parse identifiers
   var req struct {
       Identifiers []map[string]string `json:"identifiers"`
   }
   if err := json.Unmarshal(payload, &req); err != nil {
       http.Error(w, "invalid request payload", http.StatusBadRequest)
       return
   }
   // generate order and challenge
   orderID, err := generateNonce()
   if err != nil {
       http.Error(w, "unable to generate order ID", http.StatusInternalServerError)
       return
   }
   token, err := generateNonce()
   if err != nil {
       http.Error(w, "unable to generate challenge token", http.StatusInternalServerError)
       return
   }
   orders[orderID] = Order{Status: "pending"}
   challenges[token] = Challenge{Token: token, KeyAuthorization: token, Status: "pending"}
   orderTokens[orderID] = token
   // build response URLs
   orderURL := fmt.Sprintf("http://%s/acme/order/%s", r.Host, orderID)
   chalURL := fmt.Sprintf("http://%s/acme/challenge/%s", r.Host, token)
   finURL := fmt.Sprintf("http://%s/acme/finalize/%s", r.Host, orderID)
   w.Header().Set("Location", orderURL)
   w.WriteHeader(http.StatusCreated)
   resp := map[string]interface{}{
       "status":          "pending",
       "authorizations":  []string{chalURL},
       "finalize":        finURL,
   }
   json.NewEncoder(w).Encode(resp)
}

// challengeHandler serves and validates HTTP-01 challenges
func challengeHandler(w http.ResponseWriter, r *http.Request) {
   token := strings.TrimPrefix(r.URL.Path, "/acme/challenge/")
   ch, ok := challenges[token]
   if !ok {
       http.Error(w, "challenge not found", http.StatusNotFound)
       return
   }
   switch r.Method {
   case http.MethodGet:
       json.NewEncoder(w).Encode(ch)
   case http.MethodPost:
       // verify JWS to validate client ownership
       if _, _, _, err := verifyJWS(w, r); err != nil {
           return
       }
       ch.Status = "valid"
       challenges[token] = ch
       json.NewEncoder(w).Encode(map[string]string{"status": "valid", "token": token})
   default:
       http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
   }
}

// finalizeHandler accepts a CSR, calls CA service, and finalizes the order
func finalizeHandler(w http.ResponseWriter, r *http.Request) {
   if r.Method != http.MethodPost {
       http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
       return
   }
   orderID := strings.TrimPrefix(r.URL.Path, "/acme/finalize/")
   order, ok := orders[orderID]
   if !ok {
       http.Error(w, "order not found", http.StatusNotFound)
       return
   }
   token := orderTokens[orderID]
   ch := challenges[token]
   if ch.Status != "valid" {
       http.Error(w, "challenge not valid", http.StatusBadRequest)
       return
   }
   // verify JWS and extract CSR payload
   payload, _, _, err := verifyJWS(w, r)
   if err != nil {
       return
   }
   var req struct{ CSR string `json:"csr"` }
   if err := json.Unmarshal(payload, &req); err != nil {
       http.Error(w, "invalid request payload", http.StatusBadRequest)
       return
   }
   csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
   if err != nil {
       http.Error(w, "invalid CSR encoding", http.StatusBadRequest)
       return
   }
   var pemBuf bytes.Buffer
   pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
   resp, err := http.Post("http://localhost:5000/sign", "application/x-pem-file", &pemBuf)
   if err != nil {
       http.Error(w, "failed to sign CSR", http.StatusInternalServerError)
       return
   }
   defer resp.Body.Close()
   certChain, err := io.ReadAll(resp.Body)
   if err != nil {
       http.Error(w, "failed to read CA response", http.StatusInternalServerError)
       return
   }
   order.CertChain = certChain
   order.Status = "valid"
   order.CertURL = "http://localhost" + addr + "/acme/cert/" + orderID
   orders[orderID] = order
   json.NewEncoder(w).Encode(map[string]string{"status": "valid", "certificate": order.CertURL})
}

// certHandler returns the issued certificate chain
func certHandler(w http.ResponseWriter, r *http.Request) {
   orderID := strings.TrimPrefix(r.URL.Path, "/acme/cert/")
   order, ok := orders[orderID]
   if !ok || order.CertChain == nil {
       http.Error(w, "certificate not found", http.StatusNotFound)
       return
   }
   w.Header().Set("Content-Type", "application/x-pem-file")
   w.Write(order.CertChain)
}