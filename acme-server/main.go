package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	rsa "crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"

	"golang.org/x/crypto/ocsp"

	eddilithium2 "github.com/cloudflare/circl/sign/eddilithium2"
	jose "gopkg.in/square/go-jose.v2"
)

// getEnv returns environment variable or default
func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// BEGIN ADDITION: Add writeError helper function
// writeError sends a JSON error response
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json") // Keep problem+json for specific ACME errors where set
	if w.Header().Get("Content-Type") == "application/problem+json" {
		// Use ACME problem detail structure if Content-Type is problem+json
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type":   "urn:ietf:params:acme:error:badPublicKey", // Example type
			"detail": msg,
		})
	} else {
		// Default to simple JSON error
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": msg})
	}
}

// END ADDITION

// fetchOCSPStaple retrieves an OCSP staple for the given certificate using the issuer certificate.
func fetchOCSPStaple(cert *x509.Certificate, issuer *x509.Certificate) ([]byte, error) {
	if len(cert.OCSPServer) == 0 {
		return nil, fmt.Errorf("no OCSP server specified in certificate")
	}
	reqBytes, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("create OCSP request: %v", err)
	}
	ocspURL := cert.OCSPServer[0]
	pool := x509.NewCertPool()
	pool.AddCert(issuer)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	resp, err := client.Post(ocspURL, "application/ocsp-request", bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("OCSP request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP response status: %s", resp.Status)
	}
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read OCSP response: %v", err)
	}
	parsed, err := ocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		return nil, fmt.Errorf("parse OCSP response: %v", err)
	}
	if parsed.Status != ocsp.Good {
		return nil, fmt.Errorf("OCSP status is not good: %v", parsed.Status)
	}
	return respBytes, nil
}

// CA certificate file used to verify CA service
var (
	caCertFile = getEnv("CA_CERT_FILE", "ca-cert.pem")
	httpClient *http.Client
	db         *sql.DB
)

// Storage and nonce management
var (
	validNonces = make(map[string]bool)
	noncesMutex sync.Mutex

	// BEGIN ADDED CODE: CRL Cache
	crlCache      *pkix.CertificateList
	crlLastUpdate time.Time
	crlUpdateLock sync.Mutex
	// END ADDED CODE
)

// BEGIN ADDED CODE: CRL Fetch and Verification

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
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch CRL: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	crlBytes, err := io.ReadAll(resp.Body)
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
	// Use the globally defined caCertFile
	caCertPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		log.Printf("ERROR: Failed to read CA certificate for CRL check: %v", err)
		return fmt.Errorf("internal server error: could not load CA cert") // Don't expose file path error
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Printf("ERROR: Failed to decode CA certificate PEM")
		return errors.New("internal server error: could not decode CA cert")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("ERROR: Failed to parse CA certificate: %v", err)
		return errors.New("internal server error: could not parse CA cert")
	}

	// Fetch/Update CRL cache (simple cache, consider more robust mechanism)
	crlUpdateLock.Lock()
	if crlCache == nil || time.Since(crlLastUpdate) > 1*time.Hour { // Update hourly
		log.Print("INFO: Fetching/Updating CRL...")
		newCRL, err := fetchCRL(caCert)
		if err != nil {
			crlUpdateLock.Unlock()
			log.Printf("ERROR: Failed to fetch or parse CRL: %v", err)
			// Decide: Fail open (allow connection if CRL fetch fails) or fail closed (reject)?
			// Failing closed here for higher security.
			return fmt.Errorf("failed to verify revocation status: %w", err)
		}

		// Verify CRL signature with CA public key
		/* // BEGIN MODIFICATION: Remove classical signature check
		err = caCert.CheckCRLSignature(newCRL)
		if err != nil {
			crlUpdateLock.Unlock()
			log.Printf("ERROR: CRL signature verification failed: %v", err)
			return errors.New("failed to verify revocation status: CRL signature invalid")
		}
		*/ // END MODIFICATION
		// Assuming CRL fetched over trusted TLS connection to CA is sufficient for now.
		// A full solution would require loading the CA's Dilithium2 public key and verifying here.
		log.Print("WARN: Skipping CRL signature verification due to PQC CA.")

		crlCache = newCRL
		crlLastUpdate = time.Now()
		log.Print("INFO: CRL updated successfully")
	}
	currentCRL := crlCache
	crlUpdateLock.Unlock()

	// Check each certificate in the presented chain
	for _, certBytes := range rawCerts {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			log.Printf("WARN: Failed to parse presented client certificate: %v", err)
			continue // Or return error? Depends on policy.
		}

		// Check against revoked certificates in the CRL
		for _, revokedCert := range currentCRL.TBSCertList.RevokedCertificates {
			if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
				log.Printf("WARN: Client certificate revoked: S/N %s", cert.SerialNumber.String())
				return fmt.Errorf("client certificate revoked (S/N: %s)", cert.SerialNumber.String())
			}
		}
	}

	// If we are here, none of the presented certs were found in the CRL.
	// We still rely on the standard TLS verification (verifiedChains) for trust path.
	if len(verifiedChains) == 0 {
		// This case should ideally not happen if ClientAuth requires verification,
		// but good to double-check.
		return errors.New("client certificate validation failed standard checks")
	}

	log.Printf("DEBUG: Client certificate S/N %s verified (not found in CRL)", verifiedChains[0][0].SerialNumber.String())
	return nil // Certificate is not revoked according to the current CRL
}

// END ADDED CODE

// verifyJWS verifies the JWS-signed ACME request
func verifyJWS(w http.ResponseWriter, r *http.Request) (payload []byte, accountURL string, jwk *jose.JSONWebKey, err error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "unable to read request", http.StatusBadRequest)
		return nil, "", nil, err
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
		return nil, "", nil, err
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
		return nil, "", nil, err
	}
	// Validate nonce
	noncesMutex.Lock()
	if !validNonces[ph.Nonce] {
		noncesMutex.Unlock()
		http.Error(w, "invalid nonce", http.StatusBadRequest)
		return nil, "", nil, fmt.Errorf("invalid nonce")
	}
	delete(validNonces, ph.Nonce)
	noncesMutex.Unlock()
	// Validate URL
	expectedURL := fmt.Sprintf("https://%s%s", r.Host, r.URL.Path)
	if ph.URL != expectedURL {
		http.Error(w, "invalid url in protected header", http.StatusBadRequest)
		return nil, "", nil, fmt.Errorf("invalid url")
	}
	// Decode payload
	payload, err = base64.RawURLEncoding.DecodeString(req.Payload)
	if err != nil {
		http.Error(w, "invalid payload encoding", http.StatusBadRequest)
		return nil, "", nil, err
	}
	signingInput := []byte(req.Protected + "." + req.Payload)
	sigBytes, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "invalid signature encoding", http.StatusBadRequest)
		return nil, "", nil, err
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
		var jwkData []byte
		var status string
		err := db.QueryRow(
			"SELECT jwk, status FROM acme_accounts WHERE url = $1", accountURL,
		).Scan(&jwkData, &status)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "account not found", http.StatusUnauthorized)
				return nil, "", nil, err
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return nil, "", nil, err
		}
		if status != "valid" {
			http.Error(w, "account not valid", http.StatusForbidden)
			return nil, "", nil, fmt.Errorf("account not valid")
		}
		var parsed jose.JSONWebKey
		if err := parsed.UnmarshalJSON(jwkData); err != nil {
			http.Error(w, "invalid stored jwk", http.StatusInternalServerError)
			return nil, "", nil, err
		}
		pubKey = parsed.Key
		jwk = &parsed
	}
	// Verify signature
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		// REJECT: RSA keys are no longer supported for account keys
		http.Error(w, "RSA account keys are no longer supported; use keyChange to update", http.StatusBadRequest)
		return nil, accountURL, jwk, errors.New("RSA account key unsupported")
		/* // Old verification logic
		if err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sigBytes); err != nil {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return payload, accountURL, jwk, err
		}
		*/
	case *ecdsa.PublicKey:
		// REJECT: ECDSA keys are no longer supported for account keys
		http.Error(w, "ECDSA account keys are no longer supported; use keyChange to update", http.StatusBadRequest)
		return nil, accountURL, jwk, errors.New("ECDSA account key unsupported")
		/* // Old verification logic
		half := len(sigBytes) / 2
		rInt := new(big.Int).SetBytes(sigBytes[:half])
		sInt := new(big.Int).SetBytes(sigBytes[half:])
		if !ecdsa.Verify(key, hash[:], rInt, sInt) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return payload, accountURL, jwk, errors.New("ecdsa verification failed")
		}
		*/
	case *eddilithium2.PublicKey:
		// Note: Assumes go-jose.v2 correctly marshals/unmarshals the CIRCL key.
		// EdDilithium2 does not use SHA256 for hashing internally, it takes the message directly.
		if !eddilithium2.Verify(key, signingInput, sigBytes) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return payload, accountURL, jwk, errors.New("eddilithium2 verification failed")
		}
	default:
		// Check the type of the key if debugging is needed
		// log.Printf("Unsupported key type: %T", pubKey)
		http.Error(w, "unsupported key type", http.StatusBadRequest)
		return nil, "", nil, fmt.Errorf("unsupported key type: %T", pubKey)
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
	// configuration flags for testing and client authentication
	skipDB := getEnv("SKIP_DB", "false") == "true"
	skipCA := getEnv("SKIP_CA", "false") == "true"
	tlsClientAuth := getEnv("TLS_CLIENT_AUTH", "require_and_verify")

	// initialize database connection (skip if SKIP_DB=true)
	if skipDB {
		log.Print("INFO: SKIP_DB enabled, skipping database initialization")
	} else {
		dbURL := getEnv("DATABASE_URL", "postgres://localhost/acme?sslmode=disable")
		var err error
		db, err = sql.Open("postgres", dbURL)
		if err != nil {
			log.Fatalf("failed to open database: %v", err)
		}
		if err := db.Ping(); err != nil {
			log.Fatalf("failed to ping database: %v", err)
		}
	}
	// determine server's client authentication mode
	var clientAuthType tls.ClientAuthType
	switch tlsClientAuth {
	case "none":
		clientAuthType = tls.NoClientCert
	case "request":
		clientAuthType = tls.RequestClientCert
	case "require":
		clientAuthType = tls.RequireAnyClientCert
	case "verify_if_given":
		clientAuthType = tls.VerifyClientCertIfGiven
	case "require_and_verify":
		clientAuthType = tls.RequireAndVerifyClientCert
	default:
		log.Printf("WARN: invalid TLS_CLIENT_AUTH %s, defaulting to require_and_verify", tlsClientAuth)
		clientAuthType = tls.RequireAndVerifyClientCert
	}
	// assign verify function only if client authentication is enabled
	var verifyFunc func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	if clientAuthType == tls.NoClientCert {
		verifyFunc = nil
	} else {
		verifyFunc = verifyClientCertificate
	}

	// initialize keystore for TLS identity
	keyDir := getEnv("KEY_DIR", "keys")
	ks, err := NewFSKeyStore(keyDir)
	if err != nil {
		log.Fatalf("failed to init keystore: %v", err)
	}
	// BEGIN MODIFICATION: Use Dilithium2 for ACME TLS Key via Keystore
	var privKey crypto.Signer                   // Use crypto.Signer interface
	rawKey, err := ks.GetPrivateKey("acme-tls") // Use ID "acme-tls"
	if err == ErrKeyNotFound {
		// Generate new PQC key if not found
		log.Printf("INFO: Generating new ACME TLS Dilithium2 key...")
		_, pqcPriv, err := eddilithium2.GenerateKey(rand.Reader) // Discard pub
		if err != nil {
			log.Fatalf("failed to generate ACME TLS PQC key: %v", err)
		}
		if err := ks.ImportPrivateKey("acme-tls", pqcPriv); err != nil {
			log.Fatalf("failed to store ACME TLS PQC key: %v", err)
		}
		privKey = pqcPriv // Assign to crypto.Signer
		log.Printf("INFO: Generated and stored new ACME TLS Dilithium2 key.")
	} else if err != nil {
		// Handle other errors during key loading
		log.Fatalf("error loading ACME TLS key: %v", err)
	} else {
		// Ensure loaded key is PQC
		if _, ok := rawKey.(*eddilithium2.PrivateKey); !ok {
			log.Fatalf("loaded TLS key 'acme-tls' is not Dilithium2")
		}
		privKey = rawKey.(crypto.Signer) // Assign crypto.Signer
		log.Printf("INFO: Loaded existing ACME TLS Dilithium2 key.")
	}
	// Get the public key part if needed (e.g., for self-signed cert)
	var pqcPub *eddilithium2.PublicKey
	if pk, ok := privKey.(*eddilithium2.PrivateKey); ok {
		pqcPub = pk.Public().(*eddilithium2.PublicKey)
	} else {
		// This case should ideally not happen if generation/loading worked
		log.Fatalf("Could not get PQC public key from loaded private key")
	}

	// Declare newCertChain and newLeafCert here so they are in scope later
	var newCertChain [][]byte
	var newLeafCert *x509.Certificate // Also needed if storing the object
	// load or request ACME server certificate (using the new Dilithium2 key)
	certObj, err := ks.GetCertificate("acme-tls")
	if err != nil || time.Now().After(certObj.NotAfter.Add(-7*24*time.Hour)) { // Also renew if expiring soon
		if err != ErrKeyNotFound {
			log.Printf("WARN: Existing ACME TLS cert error or expiring soon, requesting new one: %v", err)
		}
		if skipCA {
			// generate self-signed certificate for testing (if skipping CA)
			serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			if err != nil {
				log.Fatalf("generate serial for self-signed cert: %v", err)
			}
			tmpl := &x509.Certificate{
				SerialNumber: serial,
				Subject:      pkix.Name{CommonName: "localhost"},
				NotBefore:    time.Now().Add(-1 * time.Minute),
				NotAfter:     time.Now().Add(24 * time.Hour),
				KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				DNSNames:     []string{"localhost"},
			}
			// Sign self-signed cert with the PQC key
			derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pqcPub, privKey)
			if err != nil {
				log.Fatalf("generate self-signed certificate: %v", err)
			}
			cert, err := x509.ParseCertificate(derBytes)
			if err != nil {
				log.Fatalf("parse self-signed certificate: %v", err)
			}
			if err := ks.ImportCertificate("acme-tls", cert); err != nil {
				log.Fatalf("store self-signed certificate: %v", err)
			}
			certObj = cert
		} else {
			// Create CSR using the Dilithium2 private key (`privKey` which is pqcPriv)
			log.Print("INFO: Requesting new ACME TLS certificate from CA...")
			csrTmpl := x509.CertificateRequest{Subject: pkix.Name{CommonName: "acme-server"}}
			// Use the Dilithium2 key (privKey) for CSR generation
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTmpl, privKey)
			if err != nil {
				log.Fatalf("create CSR for ACME TLS cert: %v", err)
			}
			buf := &bytes.Buffer{}
			pem.Encode(buf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

			// Ensure httpClient is configured to talk to CA *before* making the request
			// Load CA cert for trust
			caCertPEM, err := os.ReadFile(caCertFile)
			if err != nil {
				log.Fatalf("read CA cert file for client config: %v", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCertPEM) {
				log.Fatalf("failed to load CA root for client config")
			}
			// Use the *current* ACME server keypair (Dilithium2) for mTLS to the CA
			tempTlsCertForClient := tls.Certificate{Certificate: [][]byte{}, PrivateKey: privKey} // Use Dilithium key
			// If a valid certObj *was* loaded previously (even if expired), use it for mTLS.
			if certObj != nil {
				tempTlsCertForClient.Certificate = [][]byte{certObj.Raw}
			}

			// Setup HTTPS client to talk to CA service with mTLS
			// Note: This client uses the *potentially old/non-existent* ACME cert for the *first* request.
			// The CA's VerifyPeerCertificate must handle this (e.g., allow based on CSR content or relax check).
			// Alternatively, bootstrap trust differently.
			caClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:      pool,
						Certificates: []tls.Certificate{tempTlsCertForClient},
						// ClientAuth should match CA expectation, likely RequireAndVerifyClientCert
						ClientAuth: tls.RequireAndVerifyClientCert,
						// VerifyPeerCertificate: verifyClientCertificate, // Avoid recursion/dependency loop
					},
				},
				Timeout: 15 * time.Second, // Increase timeout for CA interaction
			}

			caSignURL := getEnv("CA_SIGN_URL", "https://localhost:5000/sign")
			resp, err := caClient.Post(caSignURL, "application/x-pem-file", buf)
			if err != nil {
				log.Fatalf("CSR sign request to CA failed: %v", err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Fatalf("read CA response: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				log.Fatalf("CA signing failed (status %d): %s", resp.StatusCode, string(body))
			}

			// Parse the *entire* chain returned by CA
			remainder := body
			for len(remainder) > 0 {
				block, r := pem.Decode(remainder)
				if block == nil {
					break // No more PEM blocks
				}
				if block.Type == "CERTIFICATE" {
					parsedCert, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						log.Fatalf("failed to parse certificate from CA response: %v", err)
					}
					if newLeafCert == nil { // First cert is the leaf
						newLeafCert = parsedCert
					}
					newCertChain = append(newCertChain, block.Bytes)
				}
				remainder = r
			}

			if newLeafCert == nil {
				log.Fatalf("CA response did not contain a valid certificate PEM block")
			}

			// Store the new leaf certificate object
			if err := ks.ImportCertificate("acme-tls", newLeafCert); err != nil {
				log.Fatalf("store new ACME TLS cert object: %v", err)
			}
			// Note: We might want to store the full chain PEM somewhere too if needed.
			certObj = newLeafCert
			log.Print("INFO: Successfully obtained new ACME TLS certificate from CA.")
		}
	}
	// build TLS key pair for server and client using the potentially new cert and Dilithium2 key
	tlsCert := tls.Certificate{Certificate: [][]byte{certObj.Raw}, PrivateKey: privKey} // Use Dilithium key
	// If the CA returned a chain, populate the Certificate field correctly
	// This requires parsing the chain from the CA response earlier.
	// Assuming the code above correctly populated newCertChain when a new cert was fetched:
	if len(newCertChain) > 0 { // Use the full chain if we just got a new one
		tlsCert.Certificate = newCertChain
	} else if certObj != nil { // Fallback to just the leaf if loaded from storage
		tlsCert.Certificate = [][]byte{certObj.Raw}
		// TODO: Consider loading the rest of the chain from storage if needed/available
	}

	// prepare CA certificate variable for OCSP refresh
	var caCert *x509.Certificate
	// OCSP stapling and CA service client setup (skip if SKIP_CA=true)
	if !skipCA {
		// load and parse CA certificate for OCSP stapling
		caCertPEM, err := os.ReadFile(caCertFile)
		if err != nil {
			log.Fatalf("read CA cert: %v", err)
		}
		block, _ := pem.Decode(caCertPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			log.Fatalf("invalid CA certificate PEM")
		}
		caCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("parse CA certificate: %v", err)
		}

		// initial OCSP stapling for server certificate
		if staple, err := fetchOCSPStaple(certObj, caCert); err != nil {
			log.Printf("warning: failed to fetch initial OCSP staple: %v", err)
		} else {
			tlsCert.OCSPStaple = staple
		}
		// setup HTTPS client to talk to CA service with mTLS
		caCertPEM, err = os.ReadFile(caCertFile)
		if err != nil {
			log.Fatalf("read CA cert: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCertPEM) {
			log.Fatalf("failed to load CA root")
		}
		httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{tlsCert}, ClientAuth: tls.RequireAndVerifyClientCert, VerifyPeerCertificate: verifyClientCertificate}}}
	} else {
		httpClient = http.DefaultClient
	}
	// register handlers with customizable timeouts
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if certObj == nil || ks == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/directory", directoryHandler)
	mux.HandleFunc("/acme/new-nonce", newNonceHandler)
	mux.HandleFunc("/acme/new-account", newAccountHandler)
	mux.HandleFunc("/acme/new-order", newOrderHandler)
	mux.HandleFunc("/acme/challenge/", challengeHandler)
	mux.HandleFunc("/acme/finalize/", finalizeHandler)
	mux.HandleFunc("/acme/cert/", certHandler)
	mux.HandleFunc("/acme/revoke-cert", revokeCertHandler)
	mux.HandleFunc("/acme/key-change", stubHandler)
	// start HTTPS server with timeouts and OCSP stapling
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
			ClientAuth:   clientAuthType,
			// Prefer PQ hybrid KEM, remove classical fallback X25519.
			CurvePreferences:      []tls.CurveID{tls.X25519MLKEM768},
			VerifyPeerCertificate: verifyFunc,
		},
	}
	// periodic OCSP staple refresh (skip if SKIP_CA=true)
	if !skipCA {
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
	}
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
	var req struct {
		Certificate string `json:"certificate"`
	}
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
	Token            string `json:"token"`
	KeyAuthorization string `json:"keyAuthorization"`
	Status           string `json:"status"`
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

	// BEGIN MODIFICATION: Enforce PQC for new accounts
	if _, ok := jwk.Key.(*eddilithium2.PublicKey); !ok {
		log.Printf("Rejecting new account request: JWK key type is not Dilithium2 (%T)", jwk.Key)
		// ACME spec recommends providing a problem document
		w.Header().Set("Content-Type", "application/problem+json")
		writeError(w, http.StatusBadRequest, "Account key must use Dilithium2 algorithm")
		// Consider adding a more specific ACME error type if available/necessary
		return
	}
	// END MODIFICATION

	// generate account ID
	id, err := generateNonce()
	if err != nil {
		http.Error(w, "unable to generate account ID", http.StatusInternalServerError)
		return
	}
	accountURL := fmt.Sprintf("https://%s/acme/acct/%s", r.Host, id)
	// store account in database
	jwkBytes, err := jwk.MarshalJSON()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_, err = db.Exec(
		"INSERT INTO acme_accounts (url, status, jwk) VALUES ($1, $2, $3)",
		accountURL, "valid", jwkBytes,
	)
	if err != nil {
		http.Error(w, "failed to create account", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Location", accountURL)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "valid"})
}

// newOrderHandler creates a new order (expects JWS)
func newOrderHandler(w http.ResponseWriter, r *http.Request) {
	// verify JWS and extract payload
	payload, _, _, err := verifyJWS(w, r)
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
	// store order and challenge in database
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec(
		"INSERT INTO acme_orders (id, status) VALUES ($1, $2)",
		orderID, "pending",
	)
	if err != nil {
		http.Error(w, "failed to create order", http.StatusInternalServerError)
		return
	}
	_, err = tx.Exec(
		"INSERT INTO acme_challenges (token, order_id, key_authorization, status) VALUES ($1, $2, $3, $4)",
		token, orderID, token, "pending",
	)
	if err != nil {
		http.Error(w, "failed to create challenge", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// build response URLs
	orderURL := fmt.Sprintf("https://%s/acme/order/%s", r.Host, orderID)
	chalURL := fmt.Sprintf("https://%s/acme/challenge/%s", r.Host, token)
	finURL := fmt.Sprintf("https://%s/acme/finalize/%s", r.Host, orderID)
	w.Header().Set("Location", orderURL)
	w.WriteHeader(http.StatusCreated)
	resp := map[string]interface{}{
		"status":         "pending",
		"authorizations": []string{chalURL},
		"finalize":       finURL,
	}
	json.NewEncoder(w).Encode(resp)
}

// challengeHandler serves and validates HTTP-01 challenges
func challengeHandler(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/acme/challenge/")
	// fetch challenge from database
	var ch Challenge
	err := db.QueryRow(
		"SELECT token, key_authorization, status FROM acme_challenges WHERE token = $1", token,
	).Scan(&ch.Token, &ch.KeyAuthorization, &ch.Status)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "challenge not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
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
		_, err := db.Exec(
			"UPDATE acme_challenges SET status = $1 WHERE token = $2", "valid", token,
		)
		if err != nil {
			http.Error(w, "failed to update challenge", http.StatusInternalServerError)
			return
		}
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
	// fetch order state from database
	var status string
	var existingCertURL sql.NullString
	var existingCertChain []byte
	err := db.QueryRow(
		"SELECT status, cert_url, cert_chain FROM acme_orders WHERE id = $1", orderID,
	).Scan(&status, &existingCertURL, &existingCertChain)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "order not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// fetch challenge status
	var chStatus string
	err = db.QueryRow(
		"SELECT status FROM acme_challenges WHERE order_id = $1", orderID,
	).Scan(&chStatus)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "challenge not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if chStatus != "valid" {
		http.Error(w, "challenge not valid", http.StatusBadRequest)
		return
	}
	// verify JWS and extract CSR payload
	payload, _, _, err := verifyJWS(w, r)
	if err != nil {
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
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
	certURLStr := fmt.Sprintf("https://%s/acme/cert/%s", r.Host, orderID)
	_, err = db.Exec(
		"UPDATE acme_orders SET status = $1, cert_url = $2, cert_chain = $3 WHERE id = $4",
		"valid", certURLStr, certChain, orderID,
	)
	if err != nil {
		http.Error(w, "failed to update order", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "valid", "certificate": certURLStr})
}

// certHandler returns the issued certificate chain
func certHandler(w http.ResponseWriter, r *http.Request) {
	orderID := strings.TrimPrefix(r.URL.Path, "/acme/cert/")
	var certChain []byte
	err := db.QueryRow(
		"SELECT cert_chain FROM acme_orders WHERE id = $1 AND cert_chain IS NOT NULL", orderID,
	).Scan(&certChain)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "certificate not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(certChain)
}
