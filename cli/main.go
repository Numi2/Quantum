package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

var version = "dev"

// SignRequest defines the payload for a signing request.
type SignRequest struct {
	ArtifactHash string          `json:"artifactHash"`
	Algorithm    string          `json:"algorithm"`
	SBOM         json.RawMessage `json:"sbom,omitempty"`
	Provenance   json.RawMessage `json:"provenance,omitempty"`
}

// SignResponse is the response from the signing service.
type SignResponse struct {
	Signature     string `json:"signature"`
	LogEntryURL   string `json:"logEntryURL"`
	SBOMURL       string `json:"sbomURL"`
	ProvenanceURL string `json:"provenanceURL"`
}

func main() {
	log.SetFlags(0)
	artifact := flag.String("artifact", "", "Path to artifact to sign")
	sbomPath := flag.String("sbom", "", "Path to SBOM JSON file to include")
	provPath := flag.String("provenance", "", "Path to SLSA provenance JSON file to include")
	server := flag.String("server", "http://localhost:7000", "Signing service URL")
	algorithm := flag.String("algorithm", "ECDSA+Dilithium", "Signing algorithm")
	timeout := flag.Duration("timeout", 10*time.Second, "Request timeout (e.g., 5s, 1m)")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n  %s --artifact app.bin --sbom app.sbom.json\n", os.Args[0])
	}
	flag.Parse()

	if *versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}
	if *artifact == "" {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(*artifact, *sbomPath, *provPath, *server, *algorithm, *timeout, *insecure); err != nil {
		log.Fatalf("error: %v", err)
	}
}

// run builds the request, sends it to the signing service, and prints the result.
func run(artifact, sbomPath, provPath, server, algorithm string, timeout time.Duration, insecure bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	artifactHash, err := computeHash(artifact)
	if err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}

	req := SignRequest{
		ArtifactHash: artifactHash,
		Algorithm:    algorithm,
	}

	if sbomPath != "" {
		b, err := os.ReadFile(sbomPath)
		if err != nil {
			return fmt.Errorf("failed to read SBOM: %w", err)
		}
		req.SBOM = json.RawMessage(b)
	}
	if provPath != "" {
		b, err := os.ReadFile(provPath)
		if err != nil {
			return fmt.Errorf("failed to read provenance: %w", err)
		}
		req.Provenance = json.RawMessage(b)
	}

	body, err := json.Marshal(&req)
	if err != nil {
		return fmt.Errorf("failed to marshal request payload: %w", err)
	}

	transport := http.DefaultTransport
	if insecure {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}
	client := &http.Client{Transport: transport}

	url := server + "/v1/signatures"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var out SignResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}

	fmt.Printf("Signature: %s\nLogEntryURL: %s\n", out.Signature, out.LogEntryURL)
	if out.SBOMURL != "" {
		fmt.Printf("SBOMURL: %s\n", out.SBOMURL)
	}
	if out.ProvenanceURL != "" {
		fmt.Printf("ProvenanceURL: %s\n", out.ProvenanceURL)
	}

	return nil
}

// computeHash streams the file at path through SHA-256 and returns the hash string.
func computeHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := h.Sum(nil)
	return fmt.Sprintf("sha256:%x", sum), nil
}
