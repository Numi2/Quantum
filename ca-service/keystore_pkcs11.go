package main

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

   "github.com/ThalesGroup/crypto11"
)

// PKCS11KeyStore wraps FSKeyStore for certificate storage and crypto11 for private keys
type PKCS11KeyStore struct {
	FS  *FSKeyStore
	ctx *crypto11.Context
}

// NewPKCS11KeyStore initializes crypto11 with PKCS#11 settings and FSKeyStore for certs
func NewPKCS11KeyStore(dir string) (KeyStore, error) {
	module := os.Getenv("PKCS11_MODULE_PATH")
	tokenLabel := os.Getenv("PKCS11_TOKEN_LABEL")
	pin := os.Getenv("PKCS11_PIN")
	if module == "" || tokenLabel == "" || pin == "" {
		return nil, errors.New("PKCS11_MODULE_PATH, PKCS11_TOKEN_LABEL, and PKCS11_PIN must be set for pkcs11 keystore")
	}
	cfg := &crypto11.Config{
		Path:       module,
		TokenLabel: tokenLabel,
		PIN:        pin,
	}
	ctx, err := crypto11.Configure(cfg)
	if err != nil {
		return nil, fmt.Errorf("crypto11 configure failed: %w", err)
	}
	fs, err := NewFSKeyStore(dir)
	if err != nil {
		return nil, fmt.Errorf("fs keystore init: %w", err)
	}
	return &PKCS11KeyStore{FS: fs, ctx: ctx}, nil
}

// GetPrivateKey retrieves a crypto.Signer from the HSM by label
func (s *PKCS11KeyStore) GetPrivateKey(id string) (crypto.PrivateKey, error) {
	signer, err := s.ctx.FindKeyPair(nil, []byte(id))
	if err != nil {
		return nil, fmt.Errorf("pkcs11 find keypair '%s': %w", id, err)
	}
	if signer == nil {
		return nil, ErrKeyNotFound
	}
	return signer, nil
}

// ImportPrivateKey is not supported for PKCS11 (key material managed by HSM)
func (s *PKCS11KeyStore) ImportPrivateKey(id string, key crypto.PrivateKey) error {
	return fmt.Errorf("ImportPrivateKey not supported for PKCS11 keystore")
}

// GetCertificate delegates to FSKeyStore
func (s *PKCS11KeyStore) GetCertificate(id string) (*x509.Certificate, error) {
	return s.FS.GetCertificate(id)
}

// ImportCertificate delegates to FSKeyStore
func (s *PKCS11KeyStore) ImportCertificate(id string, cert *x509.Certificate) error {
	return s.FS.ImportCertificate(id, cert)
}
