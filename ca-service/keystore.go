package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// ErrKeyNotFound indicates a missing key or cert in the store
var ErrKeyNotFound = errors.New("key not found in keystore")

// KeyStore defines persistent storage for keys and certificates
type KeyStore interface {
	GetPrivateKey(id string) (crypto.PrivateKey, error)
	ImportPrivateKey(id string, key crypto.PrivateKey) error
	GetCertificate(id string) (*x509.Certificate, error)
	ImportCertificate(id string, cert *x509.Certificate) error
}

// FSKeyStore stores key material on the local filesystem
type FSKeyStore struct {
	dir string
}

// NewFSKeyStore creates (and ensures) a directory for key storage
func NewFSKeyStore(dir string) (*FSKeyStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keystore dir %s: %w", dir, err)
	}
	return &FSKeyStore{dir: dir}, nil
}

// keyPath returns the path for a given key id
func (s *FSKeyStore) keyPath(id string) string {
	return filepath.Join(s.dir, id+"-key.pem")
}

// certPath returns the path for a given cert id
func (s *FSKeyStore) certPath(id string) string {
	return filepath.Join(s.dir, id+"-cert.pem")
}

// GetPrivateKey loads and parses a PEM-encoded private key
func (s *FSKeyStore) GetPrivateKey(id string) (crypto.PrivateKey, error) {
	data, err := ioutil.ReadFile(s.keyPath(id))
	if os.IsNotExist(err) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data in key file")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key2, err2 := x509.ParseECPrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key: %v, %v", err, err2)
		}
		return key2, nil
	}
	return key, nil
}

// ImportPrivateKey writes a PEM-encoded private key (PKCS#8) to disk
func (s *FSKeyStore) ImportPrivateKey(id string, key crypto.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal PKCS8 private key: %w", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := s.keyPath(id)
	if err := ioutil.WriteFile(path+".tmp", pemData, 0600); err != nil {
		return fmt.Errorf("write temp key file: %w", err)
	}
	return os.Rename(path+".tmp", path)
}

// GetCertificate loads and parses a PEM-encoded certificate
func (s *FSKeyStore) GetCertificate(id string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(s.certPath(id))
	if os.IsNotExist(err) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate PEM data in cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// ImportCertificate writes a PEM-encoded certificate to disk
func (s *FSKeyStore) ImportCertificate(id string, cert *x509.Certificate) error {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	path := s.certPath(id)
	if err := ioutil.WriteFile(path+".tmp", pemData, 0644); err != nil {
		return fmt.Errorf("write temp cert file: %w", err)
	}
	return os.Rename(path+".tmp", path)
}
