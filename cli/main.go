package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	artifact := flag.String("artifact", "", "Path to artifact to sign")
	sbomPath := flag.String("sbom", "", "Path to SBOM JSON file to include")
	provPath := flag.String("provenance", "", "Path to SLSA provenance JSON file to include")
	server := flag.String("server", "http://localhost:7000", "Signing service URL")
	algorithm := flag.String("algorithm", "ECDSA+Dilithium", "Signing algorithm")
	flag.Parse()
	if *artifact == "" {
		fmt.Println("Error: --artifact is required")
		os.Exit(1)
	}
	data, err := os.ReadFile(*artifact)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read artifact: %v\n", err)
		os.Exit(1)
	}
	hash := sha256.Sum256(data)
	hashStr := fmt.Sprintf("sha256:%x", hash[:])
	payload := map[string]string{
		"artifactHash": hashStr,
		"algorithm":    *algorithm,
	}
	if *sbomPath != "" {
		data, err := os.ReadFile(*sbomPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read SBOM: %v\n", err)
			os.Exit(1)
		}
		payload["sbom"] = string(data)
	}
	if *provPath != "" {
		data, err := os.ReadFile(*provPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read provenance: %v\n", err)
			os.Exit(1)
		}
		payload["provenance"] = string(data)
	}
	reqBody, _ := json.Marshal(payload)
	resp, err := http.Post(*server+"/v1/signatures", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "server error: %s\n", body)
		os.Exit(1)
	}
	var out struct {
		Signature     string `json:"signature"`
		LogEntryURL   string `json:"logEntryURL"`
		SBOMURL       string `json:"sbomURL"`
		ProvenanceURL string `json:"provenanceURL"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		fmt.Fprintf(os.Stderr, "invalid response: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Signature: %s\nLogEntryURL: %s\n", out.Signature, out.LogEntryURL)
	if out.SBOMURL != "" {
		fmt.Printf("SBOMURL: %s\n", out.SBOMURL)
	}
	if out.ProvenanceURL != "" {
		fmt.Printf("ProvenanceURL: %s\n", out.ProvenanceURL)
	}
}
