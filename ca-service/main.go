package main

import (
   "context"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
   "crypto/tls"
   "crypto/x509"
   "crypto/x509/pkix"
   "encoding/json"
   "encoding/pem"
   "fmt"
   "github.com/prometheus/client_golang/prometheus"
   "github.com/prometheus/client_golang/prometheus/promauto"
   "github.com/prometheus/client_golang/prometheus/promhttp"
   "go.uber.org/zap"
   "golang.org/x/crypto/ocsp"
  "io"
  "io/ioutil"
   "log"
   "math/big"
   "net/http"
   "os"
   "os/signal"
   "path/filepath"
   "sync"
   "syscall"
   "time"
)

const (
   addr = ":5000"
   // maxBodyBytes limits the size of request bodies to prevent DoS
   maxBodyBytes = 1 << 20 // 1MB
)

var (
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
)

// revocations tracks revoked certificate serials
var (
	revocations   = make(map[string]time.Time)
	revocationsMu sync.Mutex
)

// revocationsFile is the persistent store for revoked certs
// keyDir and revocationsFile are initialized in main
 var (
   keyDir         string
   revocationsFile string
   serviceHost    string
   // sugar is the global SugaredLogger
   sugar          *zap.SugaredLogger
 )
// getEnv returns the value of the environment variable named by key or defaultVal if not set or empty.
func getEnv(key, defaultVal string) string {
   if value, exists := os.LookupEnv(key); exists && value != "" {
       return value
   }
   return defaultVal
}

func main() {
   // initialize structured logger
   logger, err := zap.NewProduction()
   if err != nil {
       log.Fatalf("failed to initialize logger: %v", err)
   }
   defer logger.Sync()
   sugar = logger.Sugar()
   // determine key directory, revocations file, and public host
   keyDir = getEnv("KEY_DIR", "keys")
   serviceHost = getEnv("SERVICE_HOST", "")
   revocationsFile = filepath.Join(keyDir, "revocations.json")

   // ensure key directory exists
   if err := os.MkdirAll(keyDir, 0755); err != nil {
       sugar.Fatalf("failed to create key directory %s: %v", keyDir, err)
   }
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
	// load existing revocations
	if data, err := ioutil.ReadFile(revocationsFile); err == nil {
		var stored map[string]time.Time
		if err := json.Unmarshal(data, &stored); err != nil {
			log.Printf("warning: failed to parse revocations file: %v", err)
		} else {
			revocations = stored
		}
	}
	// Load or generate CA private key
	rawKey, err := ks.GetPrivateKey("ca-root")
	if err == ErrKeyNotFound {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("failed to generate CA key: %v", err)
		}
		if err := ks.ImportPrivateKey("ca-root", priv); err != nil {
			log.Fatalf("failed to store CA key: %v", err)
		}
		caKey = priv
	} else if err != nil {
		log.Fatalf("error loading CA key: %v", err)
	} else {
		priv, ok := rawKey.(*ecdsa.PrivateKey)
		if !ok {
			log.Fatalf("CA key is not ECDSA")
		}
		caKey = priv
	}
	// Load or generate CA certificate
	cert, err := ks.GetCertificate("ca-cert")
	if err == ErrKeyNotFound {
		serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
		if err != nil {
			log.Fatalf("failed to generate CA serial: %v", err)
		}
		tmpl := x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "PQC-Root-CA"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &caKey.PublicKey, caKey)
		if err != nil {
			log.Fatalf("failed to create CA certificate: %v", err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			log.Fatalf("failed to parse CA certificate: %v", err)
		}
		if err := ks.ImportCertificate("ca-cert", parsed); err != nil {
			log.Fatalf("failed to store CA certificate: %v", err)
		}
		caCert = parsed
	} else if err != nil {
		log.Fatalf("error loading CA certificate: %v", err)
	} else {
		caCert = cert
	}

	// register HTTP handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// readiness: ensure CA key and certificate are loaded
		if caKey == nil || caCert == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/sign", signHandler)
	mux.HandleFunc("/revoke-cert", revokeHandler)
	mux.HandleFunc("/crl", crlHandler)
	mux.HandleFunc("/ocsp", ocspHandler)
	// start HTTPS server with mTLS support
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
   // build TLS certificate for server using CA cert and key
   tlsCert := tls.Certificate{Certificate: [][]byte{caCert.Raw}, PrivateKey: caKey}
   server := &http.Server{
       Addr:         addr,
       Handler:      mux,
       ReadTimeout:  5 * time.Second,
       WriteTimeout: 10 * time.Second,
       IdleTimeout:  120 * time.Second,
       TLSConfig: &tls.Config{
           Certificates: []tls.Certificate{tlsCert},
           ClientAuth:   tls.RequireAndVerifyClientCert,
           ClientCAs:    pool,
           MinVersion:   tls.VersionTLS12,
           VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
					return fmt.Errorf("no client certificate")
				}
				leaf := verifiedChains[0][0]
				serialHex := leaf.SerialNumber.Text(16)
				revocationsMu.Lock()
				_, revoked := revocations[serialHex]
				revocationsMu.Unlock()
				if revoked {
					return fmt.Errorf("client certificate serial %s is revoked", serialHex)
				}
				return nil
			},
		},
	}
	log.Printf("CA service starting on https%s", addr)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

// ocspHandler processes OCSP requests and returns signed OCSP responses
func ocspHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reqBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read OCSP request", http.StatusBadRequest)
		return
	}
	ocspReq, err := ocsp.ParseRequest(reqBytes)
	if err != nil {
		http.Error(w, "invalid OCSP request", http.StatusBadRequest)
		return
	}
	// Check revocation status
	serialHex := ocspReq.SerialNumber.Text(16)
	revocationsMu.Lock()
	revokedAt, revoked := revocations[serialHex]
	revocationsMu.Unlock()
	status := ocsp.Good
	var revokedTime time.Time
	if revoked {
		status = ocsp.Revoked
		revokedTime = revokedAt
	}
	// Build OCSP response
	ocspResp := ocsp.Response{
		Status:           status,
		SerialNumber:     ocspReq.SerialNumber,
		ThisUpdate:       time.Now(),
		NextUpdate:       time.Now().Add(24 * time.Hour),
		RevokedAt:        revokedTime,
		RevocationReason: ocsp.Unspecified,
	}
	der, err := ocsp.CreateResponse(caCert, caCert, ocspResp, caKey)
	if err != nil {
		http.Error(w, "failed to create OCSP response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(der)
}

// signHandler reads a PEM CSR, signs it with the CA key, and returns a PEM cert chain
func signHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		http.Error(w, "invalid CSR PEM", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, "failed to parse CSR", http.StatusBadRequest)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, "CSR signature invalid", http.StatusBadRequest)
		return
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		http.Error(w, "failed to generate serial", http.StatusInternalServerError)
		return
	}
	tpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		EmailAddresses:        csr.EmailAddresses,
		// Revocation and OCSP endpoints
		CRLDistributionPoints: []string{fmt.Sprintf("https://%s/crl", r.Host)},
		OCSPServer:            []string{fmt.Sprintf("https://%s/ocsp", r.Host)},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		http.Error(w, "failed to create certificate", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
}

// saveRevocations persists revocations map to disk
func saveRevocations() {
	revocationsMu.Lock()
	defer revocationsMu.Unlock()
	data, err := json.MarshalIndent(revocations, "", "  ")
	if err != nil {
		log.Printf("failed to marshal revocations: %v", err)
		return
	}
	tmp := revocationsFile + ".tmp"
	if err := ioutil.WriteFile(tmp, data, 0644); err != nil {
		log.Printf("failed to write revocations file: %v", err)
		return
	}
	os.Rename(tmp, revocationsFile)
}

// revokeHandler adds a serial to the revocation list (mTLS authenticated)
func revokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Serial string `json:"serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	revocationsMu.Lock()
	revocations[req.Serial] = time.Now().UTC()
	revocationsMu.Unlock()
	saveRevocations()
	w.WriteHeader(http.StatusOK)
}

// crlHandler returns the current X.509 CRL in DER format
func crlHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	revocationsMu.Lock()
	revoked := make([]pkix.RevokedCertificate, 0, len(revocations))
	for serialStr, revokedAt := range revocations {
		serial := new(big.Int)
		serial.SetString(serialStr, 16)
		revoked = append(revoked, pkix.RevokedCertificate{SerialNumber: serial, RevocationTime: revokedAt})
	}
	revocationsMu.Unlock()
	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:  x509.ECDSAWithSHA256,
		RevokedCertificates: revoked,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(24 * time.Hour),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, caKey)
	if err != nil {
		http.Error(w, "failed to create CRL", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Write(crlBytes)
}
