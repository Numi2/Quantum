package main

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
   "crypto/sha256"
   "testing"

   "github.com/cloudflare/circl/sign/dilithium2"
)

// TestECDSAVerify ensures ECDSA P-256 signatures can be verified
func TestECDSAVerify(t *testing.T) {
   priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
   if err != nil {
       t.Fatalf("failed to generate ECDSA key: %v", err)
   }
   message := []byte("hello ECDSA")
   hash := sha256.Sum256(message)
   sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
   if err != nil {
       t.Fatalf("failed to sign: %v", err)
   }
   if !ecdsa.VerifyASN1(&priv.PublicKey, hash[:], sig) {
       t.Error("ECDSA signature verification failed")
   }
}

// TestDilithiumVerify ensures Dilithium2 signatures can be verified
func TestDilithiumVerify(t *testing.T) {
   scheme := dilithium2.Scheme()
   pub, priv, err := scheme.GenerateKey(rand.Reader)
   if err != nil {
       t.Fatalf("failed to generate Dilithium2 key: %v", err)
   }
   message := []byte("hello Dilithium2")
   // Dilithium signs the raw message; hashing externally is optional
   msgHash := sha256.Sum256(message)
   sig := priv.Sign(rand.Reader, msgHash[:])
   if !scheme.Verify(pub, msgHash[:], sig) {
       t.Error("Dilithium2 signature verification failed")
   }
}