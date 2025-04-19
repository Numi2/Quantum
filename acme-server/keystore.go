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

// ErrKeyNotFound indicates missing key or cert
var ErrKeyNotFound = errors.New("key not found in keystore")

// KeyStore persists keys and certificates
type KeyStore interface {
	GetPrivateKey(id string) (crypto.PrivateKey, error)
	ImportPrivateKey(id string, key crypto.PrivateKey) error
	GetCertificate(id string) (*x509.Certificate, error)
	ImportCertificate(id string, cert *x509.Certificate) error
}

// FSKeyStore stores key material on the filesystem
type FSKeyStore struct {
	dir string
}

// NewFSKeyStore ensures the key directory exists
func NewFSKeyStore(dir string) (*FSKeyStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir keystore: %w", err)
	}
	return &FSKeyStore{dir: dir}, nil
}

func (s *FSKeyStore) keyPath(id string) string {
	return filepath.Join(s.dir, id+"-key.pem")
}

func (s *FSKeyStore) certPath(id string) string {
	return filepath.Join(s.dir, id+"-cert.pem")
}

// GetPrivateKey loads a PKCS#8 PEM private key
func (s *FSKeyStore) GetPrivateKey(id string) (crypto.PrivateKey, error) {
	data, err := ioutil.ReadFile(s.keyPath(id))
	if os.IsNotExist(err) {
		return nil, ErrKeyNotFound
	} else if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM in key file")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// fallback to EC private key
		ec, err2 := x509.ParseECPrivateKey(block.Bytes)
		if err2 == nil {
			return ec, nil
		}
		return nil, fmt.Errorf("parse private key: %v, %v", err, err2)
	}
	return key, nil
}

// ImportPrivateKey stores a PKCS#8 PEM private key
func (s *FSKeyStore) ImportPrivateKey(id string, key crypto.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal PKCS8: %w", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	tmp := s.keyPath(id) + ".tmp"
	if err := ioutil.WriteFile(tmp, pemData, 0600); err != nil {
		return fmt.Errorf("write tmp key: %w", err)
	}
	return os.Rename(tmp, s.keyPath(id))
}

// GetCertificate loads a PEM certificate
func (s *FSKeyStore) GetCertificate(id string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(s.certPath(id))
	if os.IsNotExist(err) {
		return nil, ErrKeyNotFound
	} else if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no cert PEM in file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	return cert, nil
}

// ImportCertificate stores a PEM certificate
func (s *FSKeyStore) ImportCertificate(id string, cert *x509.Certificate) error {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	tmp := s.certPath(id) + ".tmp"
	if err := ioutil.WriteFile(tmp, pemData, 0644); err != nil {
		return fmt.Errorf("write tmp cert: %w", err)
	}
	return os.Rename(tmp, s.certPath(id))
}
