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

	eddilithium2 "github.com/cloudflare/circl/sign/eddilithium2"
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

// keyPath returns the path for a given key id (PEM)
func (s *FSKeyStore) keyPathPEM(id string) string {
	return filepath.Join(s.dir, id+"-key.pem")
}

// keyPathBin returns the path for a given key id (Binary/PQC)
func (s *FSKeyStore) keyPathBin(id string) string {
	return filepath.Join(s.dir, id+"-key.bin")
}

// GetPrivateKey loads and parses a private key (tries PQC .bin first, then classical .pem)
func (s *FSKeyStore) GetPrivateKey(id string) (crypto.PrivateKey, error) {
	// Try reading PQC binary key first
	binPath := s.keyPathBin(id)
	data, err := ioutil.ReadFile(binPath)
	if err == nil {
		// Found .bin file, try parsing as Dilithium2
		pqcKey := new(eddilithium2.PrivateKey)
		if parseErr := pqcKey.UnmarshalBinary(data); parseErr == nil {
			return pqcKey, nil // Successfully parsed PQC key
		} else {
			// .bin file exists but couldn't be parsed as Dilithium2
			return nil, fmt.Errorf("failed to parse PQC key from %s: %w", binPath, parseErr)
		}
	} else if !os.IsNotExist(err) {
		// Error reading .bin file other than not found
		return nil, fmt.Errorf("failed to read PQC key file %s: %w", binPath, err)
	}

	// PQC key not found or failed, try classical PEM key
	pemPath := s.keyPathPEM(id)
	data, err = ioutil.ReadFile(pemPath)
	if os.IsNotExist(err) {
		return nil, ErrKeyNotFound // Neither .bin nor .pem found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", pemPath, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data in key file %s", pemPath)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key2, err2 := x509.ParseECPrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key from %s: %v, %v", pemPath, err, err2)
		}
		return key2, nil
	}
	return key, nil
}

// ImportPrivateKey writes a private key to disk (PKCS#8 PEM for classical, binary for PQC)
func (s *FSKeyStore) ImportPrivateKey(id string, key crypto.PrivateKey) error {
	// Check if it's a PQC key we handle specially
	if pqcKey, ok := key.(*eddilithium2.PrivateKey); ok {
		der, err := pqcKey.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshal Dilithium2 private key: %w", err)
		}
		path := s.keyPathBin(id)
		if err := ioutil.WriteFile(path+".tmp", der, 0600); err != nil {
			return fmt.Errorf("write temp PQC key file: %w", err)
		}
		return os.Rename(path+".tmp", path)
	}

	// Otherwise, assume classical key and use PKCS#8 PEM encoding
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal PKCS8 private key: %w", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := s.keyPathPEM(id)
	if err := ioutil.WriteFile(path+".tmp", pemData, 0600); err != nil {
		return fmt.Errorf("write temp key file: %w", err)
	}
	return os.Rename(path+".tmp", path)
}

// certPath returns the path for a given certificate id
func (s *FSKeyStore) certPath(id string) string {
	return filepath.Join(s.dir, id+"-cert.pem")
}

// GetCertificate loads a PEM-encoded certificate
func (s *FSKeyStore) GetCertificate(id string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(s.certPath(id))
	if os.IsNotExist(err) {
		return nil, ErrKeyNotFound
	} else if err != nil {
		return nil, fmt.Errorf("failed to read cert file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate PEM in file")
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
