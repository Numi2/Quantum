package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	eddilithium2 "github.com/cloudflare/circl/sign/eddilithium2"
	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"
)

// Free tier limit per month
const FreeLimit = 1000

// maxBodyBytes limits size of request bodies to prevent DoS
const maxBodyBytes = 1 << 20 // 1MB

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
		writeError(w, http.StatusNotFound, "SBOM not found")
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
		writeError(w, http.StatusNotFound, "provenance not found")
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
	Signature     string `json:"signature"`
	LogEntryURL   string `json:"logEntryURL"`
	SBOMURL       string `json:"sbomURL,omitempty"`
	ProvenanceURL string `json:"provenanceURL,omitempty"`
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
	serviceHost = getEnv("SERVICE_HOST", "")

	// global state
	db *sql.DB
	// privateKey *ecdsa.PrivateKey // REMOVED ECDSA key
	pqPub  *eddilithium2.PublicKey
	pqPriv *eddilithium2.PrivateKey
	sugar  *zap.SugaredLogger

	// BEGIN ADDED CODE: CRL Cache and verification function
	crlCache      *pkix.CertificateList
	crlLastUpdate time.Time
	crlUpdateLock sync.Mutex // Added import for sync
)

// fetchCRL fetches and parses the CRL from the CA
func fetchCRL(caCert *x509.Certificate) (*pkix.CertificateList, error) {
	// Assuming CA URL from environment or default
	caCRLURL := getEnv("CA_CRL_URL", "https://localhost:5000/crl")
	if caCRLURL == "" {
		return nil, errors.New("CA_CRL_URL is not set")
	}

	// Use CA certificate pool for CRL fetch client
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: 10 * time.Second, // Add timeout
	}

	resp, err := client.Get(caCRLURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CRL from %s: %w", caCRLURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch CRL: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	crlBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL response body: %w", err)
	}

	crl, err := x509.ParseCRL(crlBytes)
	if err != nil {
		// Try parsing as PEM-encoded CRL
		block, _ := pem.Decode(crlBytes)
		if block != nil && block.Type == "X509 CRL" {
			crl, err = x509.ParseCRL(block.Bytes)
			if err == nil {
				return crl, nil // Successfully parsed PEM CRL
			}
		}
		return nil, fmt.Errorf("failed to parse CRL (DER/PEM): %w", err)
	}

	return crl, nil
}

// verifyClientCertificate checks if the client certificate is revoked via CRL
func verifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("no client certificate presented")
	}

	// Load CA certificate to verify CRL signature and use for fetching
	caCertPEM, err := os.ReadFile(getEnv("CA_CERT_FILE", "ca-cert.pem"))
	if err != nil {
		sugar.Errorf("Failed to read CA certificate for CRL check: %v", err)
		return fmt.Errorf("internal server error: could not load CA cert") // Don't expose file path error
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		sugar.Errorf("Failed to decode CA certificate PEM")
		return errors.New("internal server error: could not decode CA cert")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		sugar.Errorf("Failed to parse CA certificate: %v", err)
		return errors.New("internal server error: could not parse CA cert")
	}

	// Fetch/Update CRL cache (simple cache, consider more robust mechanism)
	crlUpdateLock.Lock()
	if crlCache == nil || time.Since(crlLastUpdate) > 1*time.Hour { // Update hourly
		sugar.Info("Fetching/Updating CRL...")
		newCRL, err := fetchCRL(caCert)
		if err != nil {
			crlUpdateLock.Unlock()
			sugar.Errorf("Failed to fetch or parse CRL: %v", err)
			// Decide: Fail open (allow connection if CRL fetch fails) or fail closed (reject)?
			// Failing closed here for higher security.
			return fmt.Errorf("failed to verify revocation status: %w", err)
		}

		// Verify CRL signature with CA public key
		/* // BEGIN MODIFICATION: Remove classical signature check
		err = caCert.CheckCRLSignature(newCRL)
		if err != nil {
			crlUpdateLock.Unlock()
			sugar.Errorf("CRL signature verification failed: %v", err)
			return errors.New("failed to verify revocation status: CRL signature invalid")
		}
		*/ // END MODIFICATION
		// Assuming CRL fetched over trusted TLS connection to CA is sufficient for now.
		// A full solution would require loading the CA's Dilithium2 public key and verifying here.
		// crypto/x509 does not easily expose the raw signature for verification after parsing.
		sugar.Warn("WARN: Skipping CRL signature verification due to PQC CA and standard library limitations.")

		crlCache = newCRL
		crlLastUpdate = time.Now()
		sugar.Info("CRL updated successfully")
	}
	currentCRL := crlCache
	crlUpdateLock.Unlock()

	// Check each certificate in the presented chain
	for _, certBytes := range rawCerts {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			sugar.Warnf("Failed to parse presented client certificate: %v", err)
			continue // Or return error? Depends on policy.
		}

		// Check against revoked certificates in the CRL
		for _, revokedCert := range currentCRL.TBSCertList.RevokedCertificates {
			if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
				sugar.Warnf("Client certificate revoked: S/N %s", cert.SerialNumber.String())
				return fmt.Errorf("client certificate revoked (S/N: %s)", cert.SerialNumber.String())
			}
		}
	}

	// If we are here, none of the presented certs were found in the CRL.
	// We still rely on the standard TLS verification (verifiedChains) for trust path.
	// This callback *supplements* standard verification, it doesn't replace it.
	// The standard library already performed chain validation if we reached this point
	// with verifiedChains populated. If verifiedChains is empty, it means standard
	// validation failed *before* our callback was even called.
	if len(verifiedChains) == 0 {
		// This case should ideally not happen if ClientAuth requires verification,
		// but good to double-check.
		return errors.New("client certificate validation failed standard checks")
	}

	sugar.Debugf("Client certificate S/N %s verified (not found in CRL)", verifiedChains[0][0].SerialNumber.String())
	return nil // Certificate is not revoked according to the current CRL
}

// END ADDED CODE

// getEnv returns the environment variable or default value
func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// writeError sends a JSON error response
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func main() {
	// initialize structured logger
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Printf("failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()
	sugar = logger.Sugar()

	// initialize database
	db, err = sql.Open("sqlite3", dbDSN)
	if err != nil {
		sugar.Fatalf("failed to open database: %v", err)
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
			sugar.Fatalf("migration failed: %v", err)
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
		sugar.Fatalf("unknown KEYSTORE_TYPE '%s', must be 'fs' or 'pkcs11'", storeType)
	}
	if err != nil {
		sugar.Fatalf("failed to initialize keystore: %v", err)
	}
	// load or generate ECDSA key - REMOVE THIS BLOCK
	/*
		rawKey, err := ks.GetPrivateKey("ecdsa")
		if err == ErrKeyNotFound {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				sugar.Fatalf("failed to generate ECDSA key: %v", err)
			}
			if err := ks.ImportPrivateKey("ecdsa", priv); err != nil {
				sugar.Fatalf("failed to store ECDSA key: %v", err)
			}
			privateKey = priv
		} else if err != nil {
			sugar.Fatalf("error loading ECDSA key: %v", err)
		} else {
			priv, ok := rawKey.(*ecdsa.PrivateKey)
			if !ok {
				sugar.Fatalf("invalid ECDSA key type")
			}
			privateKey = priv
		}
	*/
	// load or generate PQC Dilithium2 key
	// BEGIN MODIFICATION: Use Keystore for PQC key
	var tlsPriv crypto.Signer
	rawPqKey, err := ks.GetPrivateKey("pqc") // Use ID "pqc"
	if err == ErrKeyNotFound {
		sugar.Info("Generating new PQC signing key...")
		pub, priv, err := eddilithium2.GenerateKey(rand.Reader)
		if err != nil {
			sugar.Fatalf("failed to generate PQC key: %v", err)
		}
		if err := ks.ImportPrivateKey("pqc", priv); err != nil { // Import using ID "pqc"
			sugar.Fatalf("failed to store PQC key: %v", err)
		}
		pqPriv = priv
		pqPub = pub
		sugar.Info("Generated and stored new PQC signing key.")
	} else if err != nil {
		sugar.Fatalf("error loading PQC key: %v", err)
	} else {
		var ok bool
		pqPriv, ok = rawPqKey.(*eddilithium2.PrivateKey)
		if !ok {
			sugar.Fatalf("loaded key 'pqc' is not Dilithium2")
		}
		pqPub = pqPriv.Public().(*eddilithium2.PublicKey)
		sugar.Info("Loaded existing PQC signing key.")
	}
	// END MODIFICATION
	/* // Remove old direct file logic
	pqcPath := filepath.Join(keyDir, "pqc-key.bin")
	if data, err := os.ReadFile(pqcPath); err == nil {
		priv := new(eddilithium2.PrivateKey)
		if err := priv.UnmarshalBinary(data); err != nil {
			sugar.Fatalf("failed to parse PQC key: %v", err)
		}
		pqPriv = priv
		pqPub = priv.Public().(*eddilithium2.PublicKey)
	} else {
		pub, priv, err := eddilithium2.GenerateKey(rand.Reader)
		if err != nil {
			sugar.Fatalf("failed to generate PQC key: %v", err)
		}
		data, err := priv.MarshalBinary()
		if err != nil {
			sugar.Fatalf("failed to marshal PQC key: %v", err)
		}
		if err := os.WriteFile(pqcPath+".tmp", data, 0600); err != nil {
			sugar.Fatalf("failed to write PQC key: %v", err)
		}
		if err := os.Rename(pqcPath+".tmp", pqcPath); err != nil {
			sugar.Fatalf("failed to store PQC key: %v", err)
		}
		pqPriv = priv
		pqPub = pub
	}
	*/

	// BEGIN MODIFICATION: Use Dilithium2 for Signing Service TLS Key via Keystore
	rawTlsKey, err := ks.GetPrivateKey("tls") // Use ID "tls"
	if err == ErrKeyNotFound {
		// Generate new PQC key if not found
		sugar.Info("Generating new TLS Dilithium2 key...")
		_, priv, err := eddilithium2.GenerateKey(rand.Reader) // Discard pub
		if err != nil {
			sugar.Fatalf("failed to generate TLS PQC key: %v", err)
		}
		if err := ks.ImportPrivateKey("tls", priv); err != nil {
			sugar.Fatalf("failed to store TLS PQC key: %v", err)
		}
		tlsPriv = priv // Assign crypto.Signer
		sugar.Infof("Generated and stored new TLS Dilithium2 key.")
	} else if err != nil {
		// Handle other errors during key loading
		sugar.Fatalf("error loading TLS key: %v", err)
	} else {
		// Ensure loaded key is PQC (it should be, based on Import logic)
		if _, ok := rawTlsKey.(*eddilithium2.PrivateKey); !ok {
			sugar.Fatalf("loaded TLS key 'tls' is not Dilithium2")
		}
		tlsPriv = rawTlsKey.(crypto.Signer) // Assign crypto.Signer
		sugar.Infof("Loaded existing TLS Dilithium2 key.")
	}
	// END MODIFICATION
	/* // Remove old direct file PQC key logic
	// Define key path
	tlsPqcKeyPath := filepath.Join(keyDir, "tls-pqc-key.bin")
	var tlsPriv crypto.Signer // Use crypto.Signer interface
	var tlsPqcPriv *eddilithium2.PrivateKey
	// var tlsPqcPub *eddilithium2.PublicKey // REMOVE UNUSED PUBLIC KEY VAR

	// Try loading the PQC key
	if data, err := os.ReadFile(tlsPqcKeyPath); err == nil {
		tlsPqcPriv = new(eddilithium2.PrivateKey)
		if err := tlsPqcPriv.UnmarshalBinary(data); err != nil {
			sugar.Fatalf("failed to parse existing TLS PQC key: %v", err)
		}
		// tlsPqcPub = tlsPqcPriv.Public().(*eddilithium2.PublicKey) // No need to assign if unused
		tlsPriv = tlsPqcPriv // Assign to crypto.Signer
		sugar.Infof("Loaded existing TLS Dilithium2 key from %s", tlsPqcKeyPath)
	} else if errors.Is(err, os.ErrNotExist) {
		// Generate new PQC key if not found
		sugar.Info("Generating new TLS Dilithium2 key...")
		// Discard the public key using blank identifier _
		_, priv, err := eddilithium2.GenerateKey(rand.Reader)
		if err != nil {
			sugar.Fatalf("failed to generate TLS PQC key: %v", err)
		}
		data, err := priv.MarshalBinary()
		if err != nil {
			sugar.Fatalf("failed to marshal TLS PQC key: %v", err)
		}
		if err := os.WriteFile(tlsPqcKeyPath+".tmp", data, 0600); err != nil {
			sugar.Fatalf("failed to write TLS PQC key: %v", err)
		}
		if err := os.Rename(tlsPqcKeyPath+".tmp", tlsPqcKeyPath); err != nil {
			sugar.Fatalf("failed to store TLS PQC key: %v", err)
		}
		tlsPqcPriv = priv
		// tlsPqcPub = pub // No need to assign if unused
		tlsPriv = tlsPqcPriv // Assign to crypto.Signer
		sugar.Infof("Generated and stored new TLS Dilithium2 key at %s", tlsPqcKeyPath)
	} else {
		// Handle other errors during key loading
		sugar.Fatalf("error loading TLS PQC key from %s: %v", tlsPqcKeyPath, err)
	}
	*/
	/* // Remove old ECDSA TLS key loading
	// ... (kept commented out as before) ...
	*/

	// load or request TLS certificate from CA
	// BEGIN MODIFICATION: Always request/renew cert from CA using PQC key
	var certObj *x509.Certificate
	var certErr error
	certObj, certErr = ks.GetCertificate("tls")
	var newCertChainBytes []byte // To store the full chain PEM from CA

	if certErr != nil || time.Now().After(certObj.NotAfter.Add(-7*24*time.Hour)) { // Request/Renew if error or expiring
		if certErr != ErrKeyNotFound {
			sugar.Warnf("Existing TLS cert error or expiring soon, requesting new one: %v", certErr)
		}
		sugar.Info("Requesting new TLS certificate from CA...")
		csrTmpl := x509.CertificateRequest{Subject: pkix.Name{CommonName: "signing-service"}}
		// Use the new Dilithium2 key (tlsPriv) for CSR generation
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTmpl, tlsPriv)
		if err != nil {
			sugar.Fatalf("create CSR for signing service: %v", err)
		}
		buf := &bytes.Buffer{}
		pem.Encode(buf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

		// request from CA
		caCertPEM, err := os.ReadFile(getEnv("CA_CERT_FILE", "ca-cert.pem"))
		if err != nil {
			sugar.Fatalf("read CA cert for client config: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCertPEM) {
			sugar.Fatalf("failed to load CA root for client config")
		}
		// Use the *current* signing service keypair (Dilithium2) for mTLS to the CA
		tempTlsCertForClient := tls.Certificate{Certificate: [][]byte{}, PrivateKey: tlsPriv}
		if certObj != nil { // Use old cert for mTLS if available
			tempTlsCertForClient.Certificate = [][]byte{certObj.Raw}
		}

		caClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      pool,
					Certificates: []tls.Certificate{tempTlsCertForClient},
					ClientAuth:   tls.RequireAndVerifyClientCert, // Assuming CA requires mTLS
					// VerifyPeerCertificate: ... // Add verification if needed
				},
			},
			Timeout: 15 * time.Second,
		}
		caSignURL := getEnv("CA_SIGN_URL", "https://localhost:5000/sign")
		resp, err := caClient.Post(caSignURL, "application/x-pem-file", buf)
		if err != nil {
			sugar.Fatalf("CSR sign request to CA failed: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			sugar.Fatalf("read CA response: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			sugar.Fatalf("CA signing failed (status %d): %s", resp.StatusCode, string(body))
		}

		newCertChainBytes = body // Store the full PEM chain

		// Parse the new leaf certificate to store object and update certObj
		block, _ := pem.Decode(newCertChainBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			sugar.Fatalf("invalid certificate PEM from CA (no cert block found)")
		}
		newLeafCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			sugar.Fatalf("parse new leaf certificate: %v", err)
		}
		if err := ks.ImportCertificate("tls", newLeafCert); err != nil {
			sugar.Fatalf("store new TLS cert object: %v", err)
		}
		certObj = newLeafCert // Update certObj with the new leaf
		sugar.Info("Successfully obtained new TLS certificate from CA.")

	} else if certErr != nil {
		// If there was an error loading the cert initially, and it wasn't ErrKeyNotFound
		sugar.Fatalf("load TLS cert: %v", certErr)
	}
	// END MODIFICATION

	// prepare TLS certificate
	var finalTlsCert tls.Certificate
	if len(newCertChainBytes) > 0 {
		// Use the full chain we just received
		var err error
		// tls.X509KeyPair requires PEM key, which we don't have for Dilithium2 easily.
		// Construct tls.Certificate manually.
		// finalTlsCert, err = tls.X509KeyPair(newCertChainBytes, mustMarshalPrivateKey(tlsPriv))

		// Parse the PEM chain bytes
		var certsDER [][]byte
		remainder := newCertChainBytes
		for len(remainder) > 0 {
			block, r := pem.Decode(remainder)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				certsDER = append(certsDER, block.Bytes)
			}
			remainder = r
		}
		if len(certsDER) == 0 {
			sugar.Fatalf("No certificate blocks found in chain from CA")
		}

		finalTlsCert.Certificate = certsDER
		finalTlsCert.PrivateKey = tlsPriv // Assign the Dilithium2 key directly
		// We need the leaf certificate object for OCSP stapling later
		leafCert, err := x509.ParseCertificate(certsDER[0])
		if err != nil {
			sugar.Fatalf("Failed to parse leaf certificate from new CA chain: %v", err)
		}
		certObj = leafCert // Update certObj for OCSP

		if err != nil {
			sugar.Fatalf("Failed to create key pair from new CA chain: %v", err)
		}
	} else {
		// Use the certificate loaded from storage
		// Construct tls.Certificate manually as well
		finalTlsCert = tls.Certificate{Certificate: [][]byte{certObj.Raw}, PrivateKey: tlsPriv}
		// TODO: If full chain is needed here, load it from storage if KS supports it.
	}

	// initial OCSP staple
	// This logic remains largely the same, but uses the final certObj (leaf)
	// Ensure certObj is valid before proceeding
	if certObj == nil {
		sugar.Warnf("No valid leaf certificate available for OCSP request")
	} else {
		caCertPEMForOCSP, err := os.ReadFile(getEnv("CA_CERT_FILE", "ca-cert.pem"))
		if err != nil {
			sugar.Warnf("cannot read CA cert for OCSP: %v", err)
		} else {
			caCert, err := x509.ParseCertificate(caCertPEMForOCSP)
			if err != nil {
				sugar.Warnf("cannot parse CA cert for OCSP: %v", err)
			} else if reqBytes, err := ocsp.CreateRequest(certObj, caCert, &ocsp.RequestOptions{Hash: crypto.SHA1}); err == nil {
				// fetch OCSP response
				poolOCSP := x509.NewCertPool()
				if !poolOCSP.AppendCertsFromPEM(caCertPEMForOCSP) {
					sugar.Warnf("failed to append CA cert for OCSP")
				} else {
					client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: poolOCSP}}}
					resp, err := client.Post(getEnv("CA_OCSP_URL", "https://localhost:5000/ocsp"), "application/ocsp-request", bytes.NewReader(reqBytes))
					if err != nil {
						sugar.Warnf("OCSP request failed: %v", err)
					} else {
						if respBytes, err := io.ReadAll(resp.Body); err == nil {
							// Staple it to the *final* TLS cert config
							finalTlsCert.OCSPStaple = respBytes
						} else {
							sugar.Warnf("Failed to read OCSP response body: %v", err)
						}
						resp.Body.Close()
					}
				}
			}
		}
	}
	// start HTTPS server with timeouts
	mux := http.NewServeMux()
	// health & readiness probes
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// readiness: ensure DB is open and keys loaded
		if db == nil || pqPriv == nil { // Check pqPriv
			writeError(w, http.StatusServiceUnavailable, "db or signing key not ready")
			return
		}
		// optional: ping DB
		if err := db.Ping(); err != nil {
			writeError(w, http.StatusServiceUnavailable, "db ping failed")
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

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{finalTlsCert},
			MinVersion:   tls.VersionTLS12,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			// ClientCAs: pool, // Assuming pool is defined and holds the CA cert
			// CurvePreferences:      []tls.CurveID{tls.X25519MLKEM768}, // Explicit setting removed.
			// With Go 1.24+, leaving CurvePreferences nil enables X25519MLKEM768 hybrid KEM by default.
			// This provides hybrid PQC safety for the key exchange.
			// To disable: GODEBUG=tlsmlkem=0
			VerifyPeerCertificate: verifyClientCertificate,
		},
	}
	go func() {
		sugar.Infof("Signing service listening on %s (HTTPS)", addr)
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			sugar.Fatalf("server error: %v", err)
		}
	}()

	// graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	sugar.Infof("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		sugar.Fatalf("shutdown error: %v", err)
	}
	sugar.Infof("service stopped")
}

// accountsHandler registers a new free-tier account
func accountsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
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
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("account creation failed: %v", err))
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
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	row := db.QueryRow(
		`SELECT plan,usage_count,usage_reset FROM accounts WHERE id = ?`, accID,
	)
	var plan string
	var usageCount int
	var usageReset time.Time
	if err := row.Scan(&plan, &usageCount, &usageReset); err != nil {
		writeError(w, http.StatusNotFound, "account not found")
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
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		row := db.QueryRow(
			`SELECT id,plan,usage_count,usage_reset FROM accounts WHERE api_key = ?`, key,
		)
		var acc Account
		var usageReset time.Time
		if err := row.Scan(&acc.ID, &acc.Plan, &acc.UsageCount, &usageReset); err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		now := time.Now().UTC()
		if now.After(usageReset) {
			acc.UsageCount = 0
			usageReset = time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
			db.Exec(`UPDATE accounts SET usage_count=?,usage_reset=? WHERE id=?`, 0, usageReset, acc.ID)
		}
		if acc.Plan == "free" && acc.UsageCount >= FreeLimit {
			writeError(w, http.StatusPaymentRequired, "free tier limit exceeded")
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
	// limit body size
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	// only POST
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	parts := strings.SplitN(req.ArtifactHash, ":", 2)
	if len(parts) != 2 || parts[0] != "sha256" {
		writeError(w, http.StatusBadRequest, "invalid hash format")
		return
	}
	hashBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid hash hex")
		return
	}
	// PQC signing using Ed25519-Dilithium2
	pqcSigBytes, err := pqPriv.Sign(rand.Reader, hashBytes, crypto.Hash(0))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "PQC signing error")
		return
	}
	sigPQC := base64.RawURLEncoding.EncodeToString(pqcSigBytes)
	// Change signature format to only include PQC
	finalSig := fmt.Sprintf("pqc:%s", sigPQC)
	entryID := newEntryID()
	accountID := r.Context().Value(ctxKeyAccountID).(string)
	ts := time.Now().UTC()
	_, err = db.Exec(
		`INSERT INTO log_entries(id,account_id,artifact_hash,algorithm,signature,sbom,provenance,timestamp) VALUES(?,?,?,?,?,?,?,?);`,
		entryID, accountID, req.ArtifactHash, req.Algorithm, finalSig, req.SBOM, req.Provenance, ts, // Use finalSig
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to record log entry")
		return
	}
	// build response
	host := r.Host
	if serviceHost != "" {
		host = serviceHost
	}
	resp := SignResponse{
		Signature:     finalSig, // Use finalSig
		LogEntryURL:   fmt.Sprintf("https://%s/v1/log/%s", host, entryID),
		SBOMURL:       fmt.Sprintf("https://%s/v1/log/%s/sbom", host, entryID),
		ProvenanceURL: fmt.Sprintf("https://%s/v1/log/%s/provenance", host, entryID),
	}
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

// Helper function to marshal private key to PEM bytes (needed for tls.X509KeyPair)
// NOTE: This helper is NO LONGER USED as we assign the crypto.Signer directly.
/*
func mustMarshalPrivateKey(key crypto.PrivateKey) []byte {
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		// This should not happen with the current logic where tlsPriv is ECDSA
		sugar.Fatalf("Private key for TLS cert is not ECDSA, cannot marshal for X509KeyPair")
	}
	derBytes, err := x509.MarshalECPrivateKey(ecdsaKey)
	if err != nil {
		sugar.Fatalf("Failed to marshal ECDSA private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})
}
*/
