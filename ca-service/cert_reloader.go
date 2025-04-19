package main

import (
   "crypto/tls"
   "errors"
   "sync"
)

// CertReloader dynamically reloads TLS certificates from a KeyStore
type CertReloader struct {
   ks KeyStore
   id string
   mu sync.RWMutex
   cert *tls.Certificate
}

// NewCertReloader creates a new CertReloader for a given keystore and cert ID
func NewCertReloader(ks KeyStore, id string) *CertReloader {
   return &CertReloader{ks: ks, id: id}
}

// Reload loads the certificate and private key from the KeyStore
func (c *CertReloader) Reload() error {
   // Load certificate
   x509Cert, err := c.ks.GetCertificate(c.id)
   if err != nil {
       return err
   }
   // Load private key
   privKey, err := c.ks.GetPrivateKey(c.id)
   if err != nil {
       return err
   }
   // Create tls.Certificate
   tlsCert := tls.Certificate{Certificate: [][]byte{x509Cert.Raw}, PrivateKey: privKey}
   c.mu.Lock()
   c.cert = &tlsCert
   c.mu.Unlock()
   return nil
}

// GetCertificate returns the currently loaded certificate for TLS handshakes
func (c *CertReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
   c.mu.RLock()
   defer c.mu.RUnlock()
   if c.cert == nil {
       return nil, errors.New("certificate not loaded")
   }
   return c.cert, nil
}