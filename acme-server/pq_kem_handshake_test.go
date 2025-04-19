//go:build integration
// +build integration

package main_test

import (
   "crypto/tls"
   "net"
   "os"
   "os/exec"
   "testing"
   "time"
)

// TestPQKEMHandshake starts the ACME server configured with PQ KEM support,
// performs a TLS 1.3 handshake preferring the hybrid X25519MLKEM768 curve,
// and then tears down the server.
func TestPQKEMHandshake(t *testing.T) {
   t.Parallel()
   // Build the ACME server binary
   // Build the ACME server binary (all package files)
   build := exec.Command("go", "build", "-o", "acme-server-bin", ".")
   build.Dir = "."
   if out, err := build.CombinedOutput(); err != nil {
       t.Fatalf("failed to build acme-server: %v, output: %s", err, string(out))
   }
   defer os.Remove("acme-server-bin")

   // Prepare a clean key directory
   keyDir := "keys_test"
   os.RemoveAll(keyDir)

   // Start the server with testing overrides
   cmd := exec.Command("./acme-server-bin")
   cmd.Env = append(os.Environ(),
       "SKIP_DB=true",
       "SKIP_CA=true",
       "TLS_CLIENT_AUTH=none",
       "KEY_DIR="+keyDir,
   )
   cmd.Dir = "."
   if err := cmd.Start(); err != nil {
       t.Fatalf("failed to start acme-server: %v", err)
   }
   // Ensure server is torn down
   defer func() {
       cmd.Process.Kill()
       cmd.Wait()
       os.RemoveAll(keyDir)
   }()

   // Wait until the server is listening
   addr := "localhost:4000"
   deadline := time.Now().Add(5 * time.Second)
   for time.Now().Before(deadline) {
       conn, err := net.Dial("tcp", addr)
       if err == nil {
           conn.Close()
           break
       }
       time.Sleep(100 * time.Millisecond)
   }

   // Perform a TLS handshake preferring the PQ hybrid curve
   config := &tls.Config{
       MinVersion:         tls.VersionTLS13,
       InsecureSkipVerify: true,
       CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
   }
   conn, err := tls.Dial("tcp", addr, config)
   if err != nil {
       t.Fatalf("TLS handshake failed: %v", err)
   }
   defer conn.Close()
   state := conn.ConnectionState()
   if state.Version != tls.VersionTLS13 {
       t.Errorf("expected TLS1.3, got %x", state.Version)
   }
}