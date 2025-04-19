package main

import (
   "bytes"
   "crypto"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
   "crypto/sha256"
   "crypto/tls"
   "crypto/x509"
   "crypto/x509/pkix"
   "encoding/base64"
   "encoding/json"
   "encoding/pem"
   "fmt"
   "io"
   "log"
   "net/http"
   "os"
   "strings"
   "sync"
   "time"

   "golang.org/x/crypto/ocsp"

   jose "gopkg.in/square/go-jose.v2"
)

// getEnv returns environment variable or default
func getEnv(key, def string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return def
}

// CA certificate file used to verify CA service
var (
    caCertFile = getEnv("CA_CERT_FILE", "ca-cert.pem")
    httpClient *http.Client
)

// Storage and nonce management
var (
    validNonces = make(map[string]bool)
    noncesMutex sync.Mutex

    storeMutex sync.Mutex
)

// Persistent store structure
type acmeStore struct {
    Accounts    map[string]Account   `json:"accounts"`
    Orders      map[string]Order     `json:"orders"`
    Challenges  map[string]Challenge `json:"challenges"`
    OrderTokens map[string]string    `json:"orderTokens"`
}

// loadStore initializes in-memory stores from disk
func loadStore() {
    f, err := os.Open("acme-store.json")
    if err != nil {
        if !os.IsNotExist(err) {
            log.Printf("failed to open store file: %v", err)
        }
        return
    }
    defer f.Close()
    var s acmeStore
    if err := json.NewDecoder(f).Decode(&s); err != nil {
        log.Printf("failed to decode store: %v", err)
        return
    }
    accounts = s.Accounts
    orders = s.Orders
    challenges = s.Challenges
    orderTokens = s.OrderTokens
}

// saveStore writes in-memory stores to disk
func saveStore() {
    storeMutex.Lock()
    defer storeMutex.Unlock()
    tmpFile := "acme-store.json.tmp"
    f, err := os.Create(tmpFile)
    if err != nil {
        log.Printf("failed to create store file: %v", err)
        return
    }
    if err := json.NewEncoder(f).Encode(acmeStore{
        Accounts:    accounts,
        Orders:      orders,
        Challenges:  challenges,
        OrderTokens: orderTokens,
    }); err != nil {
        log.Printf("failed to encode store: %v", err)
    }
    f.Close()
    os.Rename(tmpFile, "acme-store.json")
}

// verifyJWS verifies the JWS-signed ACME request
func verifyJWS(w http.ResponseWriter, r *http.Request) (payload []byte, accountURL string, jwk *jose.JSONWebKey, err error) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "unable to read request", http.StatusBadRequest)
        return
    }
    defer r.Body.Close()
    var req struct {
        Protected string `json:"protected"`
        Payload   string `json:"payload"`
        Signature string `json:"signature"`
    }
    if err := json.Unmarshal(body, &req); err != nil {
        http.Error(w, "invalid JWS request", http.StatusBadRequest)
        return nil, "", nil, err
    }
    phBytes, err := base64.RawURLEncoding.DecodeString(req.Protected)
    if err != nil {
        http.Error(w, "invalid protected header encoding", http.StatusBadRequest)
        return
    }
    var ph struct {
        Alg   string                 `json:"alg"`
        Nonce string                 `json:"nonce"`
        URL   string                 `json:"url"`
        Jwk   map[string]interface{} `json:"jwk,omitempty"`
        Kid   string                 `json:"kid,omitempty"`
    }
    if err := json.Unmarshal(phBytes, &ph); err != nil {
        http.Error(w, "invalid protected header", http.StatusBadRequest)
        return
    }
    // Validate nonce
    noncesMutex.Lock()
    if !validNonces[ph.Nonce] {
        noncesMutex.Unlock()
        http.Error(w, "invalid nonce", http.StatusBadRequest)
        return
    }
    delete(validNonces, ph.Nonce)
    noncesMutex.Unlock()
    // Validate URL
    expectedURL := fmt.Sprintf("https://%s%s", r.Host, r.URL.Path)
    if ph.URL != expectedURL {
        http.Error(w, "invalid url in protected header", http.StatusBadRequest)
        return
    }
    // Decode payload
    payload, err = base64.RawURLEncoding.DecodeString(req.Payload)
    if err != nil {
        http.Error(w, "invalid payload encoding", http.StatusBadRequest)
        return
    }
    signingInput := []byte(req.Protected + "." + req.Payload)
    sigBytes, err := base64.RawURLEncoding.DecodeString(req.Signature)
    if err != nil {
        http.Error(w, "invalid signature encoding", http.StatusBadRequest)
        return
    }
    // Determine public key
    var pubKey interface{}
    if ph.Jwk != nil {
        jwkJSON, _ := json.Marshal(ph.Jwk)
        var parsed jose.JSONWebKey
        if err := parsed.UnmarshalJSON(jwkJSON); err != nil {
            http.Error(w, "invalid jwk", http.StatusBadRequest)
            return nil, "", nil, err
        }
        pubKey = parsed.Key
        jwk = &parsed
    } else {
        accountURL = ph.Kid
        acct, ok := accounts[accountURL]
        if !ok {
            http.Error(w, "account not found", http.StatusUnauthorized)
            return
        }
        pubKey = acct.Key.Key
        jwk = &acct.Key
    }
    hash := sha256.Sum256(signingInput)
    // Verify signature
    switch key := pubKey.(type) {
    case *rsa.PublicKey:
        if err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sigBytes); err != nil {
            http.Error(w, "invalid signature", http.StatusUnauthorized)
            return payload, accountURL, jwk, err
        }
    case *ecdsa.PublicKey:
        half := len(sigBytes) / 2
        rInt := new(big.Int).SetBytes(sigBytes[:half])
        sInt := new(big.Int).SetBytes(sigBytes[half:])
        if !ecdsa.Verify(key, hash[:], rInt, sInt) {
            http.Error(w, "invalid signature", http.StatusUnauthorized)
            return payload, accountURL, jwk, errors.New("ecdsa verification failed")
        }
    default:
        http.Error(w, "unsupported key type", http.StatusBadRequest)
        return
    }
    return payload, accountURL, jwk, nil
}


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
   NewNonce:   "https://localhost" + addr + "/acme/new-nonce",
   NewAccount: "https://localhost" + addr + "/acme/new-account",
   NewOrder:   "https://localhost" + addr + "/acme/new-order",
   RevokeCert: "https://localhost" + addr + "/acme/revoke-cert",
   KeyChange:  "https://localhost" + addr + "/acme/key-change",
}

func main() {
   // load ACME state
   loadStore()

   // initialize keystore for TLS identity
   keyDir := getEnv("KEY_DIR", "keys")
   ks, err := NewFSKeyStore(keyDir)
   if err != nil {
       log.Fatalf("failed to init keystore: %v", err)
   }
   // load or generate ACME server private key
   rawKey, err := ks.GetPrivateKey("acme-tls")
   var privKey *ecdsa.PrivateKey
   if err == ErrKeyNotFound {
       p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
       if err != nil {
           log.Fatalf("generate ACME TLS key: %v", err)
       }
       if err := ks.ImportPrivateKey("acme-tls", p); err != nil {
           log.Fatalf("store ACME TLS key: %v", err)
       }
       privKey = p
   } else if err != nil {
       log.Fatalf("load ACME TLS key: %v", err)
   } else {
       var ok bool
       privKey, ok = rawKey.(*ecdsa.PrivateKey)
       if !ok {
           log.Fatalf("ACME key is not ECDSA")
       }
   }
   // load or request ACME server certificate from CA
   certObj, err := ks.GetCertificate("acme-tls")
   if err == ErrKeyNotFound {
       // create CSR
       csrTmpl := x509.CertificateRequest{Subject: pkix.Name{CommonName: "acme-server"}}
       csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTmpl, privKey)
       if err != nil {
           log.Fatalf("create CSR: %v", err)
       }
       buf := &bytes.Buffer{}
       pem.Encode(buf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
       // request from CA service
       caCertPEM, err := os.ReadFile(caCertFile)
       if err != nil {
           log.Fatalf("read CA cert: %v", err)
       }
       pool := x509.NewCertPool()
       if !pool.AppendCertsFromPEM(caCertPEM) {
           log.Fatalf("failed to load CA root")
       }
       httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
       resp, err := httpClient.Post("https://localhost:5000/sign", "application/x-pem-file", buf)
       if err != nil {
           log.Fatalf("CSR sign request failed: %v", err)
       }
       body, err := io.ReadAll(resp.Body)
       resp.Body.Close()
       if err != nil {
           log.Fatalf("read CA response: %v", err)
       }
       // parse leaf certificate
       block, _ := pem.Decode(body)
       if block == nil || block.Type != "CERTIFICATE" {
           log.Fatalf("invalid certificate PEM")
       }
       cert, err := x509.ParseCertificate(block.Bytes)
       if err != nil {
           log.Fatalf("parse certificate: %v", err)
       }
       if err := ks.ImportCertificate("acme-tls", cert); err != nil {
           log.Fatalf("store ACME cert: %v", err)
       }
       certObj = cert
   } else if err != nil {
       log.Fatalf("load ACME cert: %v", err)
   }
   // build TLS key pair for server and client
   tlsCert := tls.Certificate{Certificate: [][]byte{certObj.Raw}, PrivateKey: privKey}
   // initial OCSP stapling for server certificate
   if staple, err := fetchOCSPStaple(certObj, caCert); err != nil {
       log.Printf("warning: failed to fetch initial OCSP staple: %v", err)
   } else {
       tlsCert.OCSPStaple = staple
   }
   // setup HTTPS client to talk to CA service with mTLS
   caCertPEM, err := os.ReadFile(caCertFile)
   if err != nil {
       log.Fatalf("read CA cert: %v", err)
   }
   pool := x509.NewCertPool()
   if !pool.AppendCertsFromPEM(caCertPEM) {
       log.Fatalf("failed to load CA root")
   }
   httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{tlsCert}}}}
   // register handlers
   // health & readiness probes
   http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
   http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
       // readiness: ensure keystore and cert are initialized
       if certObj == nil || ks == nil {
           http.Error(w, "not ready", http.StatusServiceUnavailable)
           return
       }
       w.WriteHeader(http.StatusOK)
   })
   http.HandleFunc("/directory", directoryHandler)
   http.HandleFunc("/acme/new-nonce", newNonceHandler)
   http.HandleFunc("/acme/new-account", newAccountHandler)
   http.HandleFunc("/acme/new-order", newOrderHandler)
   http.HandleFunc("/acme/challenge/", challengeHandler)
   http.HandleFunc("/acme/finalize/", finalizeHandler)
   http.HandleFunc("/acme/cert/", certHandler)
   http.HandleFunc("/acme/revoke-cert", revokeCertHandler)
   http.HandleFunc("/acme/key-change", stubHandler)
   // start HTTPS server with OCSP stapling
   server := &http.Server{
       Addr:    addr,
       Handler: nil,
       TLSConfig: &tls.Config{
           Certificates: []tls.Certificate{tlsCert},
           MinVersion:   tls.VersionTLS12,
       },
   }
   // periodic OCSP staple refresh
   go func() {
       for {
           time.Sleep(12 * time.Hour)
           if staple, err := fetchOCSPStaple(certObj, caCert); err != nil {
               log.Printf("OCSP staple refresh failed: %v", err)
           } else {
               server.TLSConfig.Certificates[0].OCSPStaple = staple
           }
       }
   }()
   log.Printf("ACME server starting on https%s", addr)
   log.Fatal(server.ListenAndServeTLS("", ""))
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
   noncesMutex.Lock()
   validNonces[nonce] = true
   noncesMutex.Unlock()
   w.Header().Set("Replay-Nonce", nonce)
   w.WriteHeader(http.StatusOK)
}

// stubHandler is a placeholder for unimplemented ACME endpoints
func stubHandler(w http.ResponseWriter, r *http.Request) {
   http.Error(w, "not implemented", http.StatusNotImplemented)
}
// revokeCertHandler handles ACME certificate revocation (JWS+CSR parsing)
func revokeCertHandler(w http.ResponseWriter, r *http.Request) {
   // expect POST with JWS payload containing certificate DER (base64)
   if r.Method != http.MethodPost {
       http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
       return
   }
   payload, _, _, err := verifyJWS(w, r)
   if err != nil {
       return
   }
   var req struct { Certificate string `json:"certificate"` }
   if err := json.Unmarshal(payload, &req); err != nil {
       http.Error(w, "invalid request payload", http.StatusBadRequest)
       return
   }
   certDER, err := base64.RawURLEncoding.DecodeString(req.Certificate)
   if err != nil {
       http.Error(w, "invalid certificate encoding", http.StatusBadRequest)
       return
   }
   cert, err := x509.ParseCertificate(certDER)
   if err != nil {
       http.Error(w, "failed to parse certificate", http.StatusBadRequest)
       return
   }
   serial := cert.SerialNumber.Text(16)
   // send revoke request to CA service
   body, _ := json.Marshal(map[string]string{"serial": serial})
   resp, err := httpClient.Post(getEnv("CA_REVOKE_URL", "https://localhost:5000/revoke-cert"), "application/json", bytes.NewReader(body))
   if err != nil || resp.StatusCode != http.StatusOK {
       http.Error(w, "failed to revoke certificate", http.StatusInternalServerError)
       return
   }
   w.WriteHeader(http.StatusOK)
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
   Status string          `json:"status"`
   Key    jose.JSONWebKey `json:"key"`
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
   accountURL := fmt.Sprintf("https://%s/acme/acct/%s", r.Host, id)
   // store account
   accounts[accountURL] = Account{Status: "valid", Key: *jwk}
   saveStore()
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
   saveStore()
   // build response URLs
   orderURL := fmt.Sprintf("https://%s/acme/order/%s", r.Host, orderID)
   chalURL := fmt.Sprintf("https://%s/acme/challenge/%s", r.Host, token)
   finURL := fmt.Sprintf("https://%s/acme/finalize/%s", r.Host, orderID)
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
       saveStore()
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
   // call CA service over HTTPS
   resp, err := httpClient.Post("https://localhost:5000/sign", "application/x-pem-file", &pemBuf)
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
   order.CertURL = fmt.Sprintf("https://%s/acme/cert/%s", r.Host, orderID)
   orders[orderID] = order
   saveStore()
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