package main

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
   "crypto/x509"
   "crypto/x509/pkix"
   "encoding/pem"
   "io"
   "log"
   "math/big"
   "net/http"
   "time"
)

const addr = ":5000"

var (
   caCert *x509.Certificate
   caKey  *ecdsa.PrivateKey
)

func main() {
   // Initialize CA root key and certificate
   priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
   if err != nil {
       log.Fatalf("failed to generate CA key: %v", err)
   }
   caKey = priv
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
   der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
   if err != nil {
       log.Fatalf("failed to create CA certificate: %v", err)
   }
   cert, err := x509.ParseCertificate(der)
   if err != nil {
       log.Fatalf("failed to parse CA certificate: %v", err)
   }
   caCert = cert

   http.HandleFunc("/sign", signHandler)
   log.Printf("CA service starting on %s", addr)
   log.Fatal(http.ListenAndServe(addr, nil))
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