# Quantum-Safe PKI Project Documentation

## 1. Introduction

This document provides comprehensive documentation for the Quantum-Safe Public Key Infrastructure (PKI) project. This project implements a set of Go-based microservices demonstrating a modern, extensible PKI capable of handling post-quantum cryptography (PQC) alongside traditional algorithms. It includes an ACMEv2 compliant server, a Certificate Authority (CA), a signing service, a transparency log, a device provisioning service, and a command-line interface (CLI).

## 2. Project Overview

The goal of this project is to showcase the integration of PQC algorithms, specifically EdDilithium2 for digital signatures and hybrid KEMs (X25519+MLKEM768) for TLS key exchange, into a functional PKI and certificate management ecosystem.

**Key Features:**

*   **Hybrid Cryptography:** Utilizes both classical (ECDSA P-256) and PQC (EdDilithium2) algorithms.
*   **ACME v2 Compliance:** The `acme-server` implements the ACME protocol for automated certificate management.
*   **PQC Signatures:**
    *   The `ca-service` issues certificates signed with EdDilithium2.
    *   The `acme-server` supports account key binding and request signing using EdDilithium2 JWS.
    *   The `signing-service` provides hybrid ECDSA+PQC signatures.
*   **PQ Hybrid KEM:** TLS endpoints (ACME, CA, Signing Service) prefer X25519+MLKEM768 hybrid key exchange.
*   **Certificate Revocation:** Implements CRL distribution and OCSP checking. Client certificate verification includes CRL checks.
*   **Transparency Log:** Records issued certificates for auditability (`transparency-log-service`).
*   **Modular Architecture:** Services are designed as independent microservices.
*   **Supply Chain Security:** CI pipeline generates SBOMs and SLSA provenance attestations.

## 3. Architecture

The project consists of the following microservices:

*   **`ca-service`**:
    *   Issues X.509 certificates.
    *   Signs issued certificates using an EdDilithium2 private key.
    *   Provides endpoints for signing CSRs (`/sign`), CRL distribution (`/crl`), and OCSP (`/ocsp`).
    *   Uses an ECDSA P-256 key for its own root CA certificate and TLS identity.
    *   Supports mTLS for client authentication and performs CRL checks on client certs.
    *   Supports key storage via filesystem (`fs`) or PKCS#11 (`pkcs11`).
*   **`acme-server`**:
    *   Implements ACME v2 protocol endpoints (`/directory`, `/acme/new-nonce`, `/acme/new-account`, `/acme/new-order`, `/acme/challenge/`, `/acme/finalize/`, `/acme/cert/`, `/acme/revoke-cert`).
    *   Interacts with `ca-service` to issue certificates.
    *   Requires a PostgreSQL database for state management (accounts, orders, challenges).
    *   Supports JWS validation using RSA, ECDSA, and EdDilithium2 keys.
    *   Supports configurable TLS client authentication (including CRL checks via `verifyClientCertificate`).
    *   Supports OCSP stapling for its own TLS certificate.
    *   Includes testing hooks (`SKIP_DB`, `SKIP_CA`, `TLS_CLIENT_AUTH`).
*   **`signing-service`**:
    *   Signs arbitrary artifact hashes using a hybrid ECDSA + EdDilithium2 signature scheme.
    *   Requires authentication via API Keys (`X-API-Key` header).
    *   Implements rate limiting for a 'free' tier.
    *   Stores signing logs, SBOMs, and provenance in a SQLite database (`signing.db` by default).
    *   Provides endpoints for account creation (`/v1/accounts`), signing (`/v1/signatures`), log retrieval (`/v1/log/{id}`), SBOM retrieval (`/v1/log/{id}/sbom`), and provenance retrieval (`/v1/log/{id}/provenance`).
    *   Supports mTLS with CRL checks.
    *   Supports key storage via filesystem (`fs`) or PKCS#11 (`pkcs11`).
*   **`transparency-log-service`**:
    *   Implements a Certificate Transparency (CT) log.
    *   Stores log entries in an append-only file (`transparency.log` by default).
    *   Provides endpoints for adding certificate chains (`/ct/v1/add-chain`), getting the Signed Tree Head (STH) (`/ct/v1/get-sth`), retrieving entries (`/ct/v1/get-entries`), and getting Merkle audit proofs (`/ct/v1/get-proof-by-hash`).
    *   Signs the STH using an ECDSA P-256 key.
*   **`device-service`**:
    *   Simple service for provisioning device certificates.
    *   Accepts CSRs, forwards them to the `ca-service` for signing.
    *   Requires API key authentication (`X-API-Key` header).
*   **`cli`**:
    *   Command-line tool to interact with the `signing-service`.
    *   Computes artifact hashes (SHA-256).
    *   Sends signing requests, optionally including SBOM and provenance data.
    *   Prints the returned signature and log URLs.

**Interactions:**

*   `acme-server` calls `ca-service` `/sign` endpoint to get certificates for ACME clients.
*   `acme-server` calls `ca-service` `/revoke-cert` endpoint.
*   `acme-server` (optionally) calls `ca-service` `/crl` endpoint for client certificate validation.
*   `device-service` calls `ca-service` `/sign` endpoint.
*   `cli` calls `signing-service` `/v1/signatures` endpoint.
*   TLS clients connecting to `acme-server`, `ca-service`, `signing-service` may undergo mTLS verification including CRL checks against the `ca-service` CRL.
*   `acme-server`, `ca-service`, `signing-service` fetch OCSP staples for their own certificates from the `ca-service` `/ocsp` endpoint.

## 4. Prerequisites

*   **Go:** Version 1.24.2 or newer.
*   **PostgreSQL:** Required for the `acme-server`. A `psql` client is needed to run database migrations.
*   **(Optional) Docker:** For containerized deployment.
*   **(Optional) PKCS#11 Hardware/Software:** If using `KEYSTORE_TYPE=pkcs11`.

## 5. Building the Services

1.  **Clone:** `git clone <repository-url> && cd <repository-directory>`
2.  **Create `bin` directory:** `mkdir -p bin`
3.  **Build:**
    ```bash
    go build -o bin/ca-service ./ca-service
    go build -o bin/acme-server ./acme-server
    go build -o bin/device-service ./device-service
    go build -o bin/signing-service ./signing-service
    go build -o bin/cli ./cli
    go build -o bin/transparency-log-service ./transparency-log-service
    ```
    Binaries will be located in the `bin/` directory.

## 6. Configuration

Configuration is primarily managed through environment variables. Key files (certificates, private keys) are expected in specific locations, often configurable via environment variables like `KEY_DIR`.

**Common:**

*   `KEY_DIR`: Directory to store/load cryptographic keys and certificates (Default: `keys`).
*   `KEYSTORE_TYPE`: Method for storing private keys. `fs` (filesystem PEM/DER files) or `pkcs11` (PKCS#11 HSM). (Default: `fs`)
*   `CA_CERT_FILE`: Path to the CA root certificate PEM file (used by clients and services for verification). (Default: `ca-cert.pem`)
*   `CA_CRL_URL`: URL to fetch the Certificate Revocation List from the CA. (Default: `https://localhost:5000/crl`)
*   `CA_SIGN_URL`: URL of the CA's CSR signing endpoint. (Default: `https://localhost:5000/sign`)
*   `CA_OCSP_URL`: URL of the CA's OCSP responder. (Default: `https://localhost:5000/ocsp`)
*   `SERVICE_HOST`: Publicly accessible hostname for the service (used in URLs generated by the service). (Default: derived from request Host header or empty)

**`ca-service`:**

*   `PORT_CA` / `ADDR`: Listen address (Default: `:5000`)
*   Uses keys: `ca-root` (ECDSA), `ca-pqc-key.bin` (EdDilithium2), `ca-cert` (Certificate) within `KEY_DIR`.
*   Stores revocations in `revocations.json` within `KEY_DIR`.

**`acme-server`:**

*   `PORT_ACME` / `ADDR`: Listen address (Default: `:4000`)
*   `DATABASE_URL`: PostgreSQL connection string (e.g., `postgres://user:pass@host:port/dbname?sslmode=disable`).
*   `GODEBUG`: Set to `tls13kem=1` in the environment to activate the preferred hybrid KEM (X25519+MLKEM768) configured in the code. Set to `tls13kem=0` to force fallback to classical KEMs only (like X25519). The Go runtime defaults to `tls13kem=0` unless specified.
*   `TLS_CLIENT_AUTH`: Controls TLS client authentication mode (`none`, `request`, `require`, `verify_if_given`, `require_and_verify`). (Default: `require_and_verify`).
*   `SKIP_DB`: Set to `true` to skip database initialization. (Default: `false`)
*   `SKIP_CA`: Set to `true` to use a self-signed certificate instead of requesting from `ca-service`. (Default: `false`)
*   Uses keys: `acme-tls` (ECDSA Private Key), `acme-tls` (Certificate) within `KEY_DIR`.

**`signing-service`:**

*   `SIGNING_ADDR` / `ADDR`: Listen address (Default: `:7000`)
*   `DB_DSN`: SQLite database file path. (Default: `signing.db`)
*   Uses keys: `ecdsa` (ECDSA Private Key), `pqc-key.bin` (EdDilithium2 Private Key), `tls` (ECDSA Private Key for TLS), `tls` (Certificate for TLS) within `KEY_DIR`.

**`transparency-log-service`:**

*   `addr`: Listen address for main API. (Default: `:8085`)
*   `metrics-addr`: Listen address for Prometheus metrics. (Default: `:9095`)
*   `storage-file`: Path to the append-only log file. (Default: `transparency.log`)
*   `sth-key-file`: Path to the ECDSA private key for signing STHs. (Default: `sth_key.pem`)

**`device-service`:**

*   `ADDR`: Listen address (Default: `:6000`)
*   `DEVICE_API_KEY`: Required API key for authenticating requests.
*   `CA_SIGN_URL`: URL of the CA's signing endpoint. (Default: `http://localhost:5000/sign` - Note: Defaults to HTTP, ensure transport security if needed).

**`cli`:**

*   Uses command-line flags (see `--help`).

## 7. Running the Services

Ensure prerequisites (Go, PostgreSQL) are met and environment variables are set.

1.  **Database Setup (for `acme-server`):**
    *   Create the PostgreSQL database and user specified in `DATABASE_URL`.
    *   Run migrations: `psql "$DATABASE_URL" -f acme-server/migrations/0001_create_acme_tables.up.sql`

2.  **Run Each Service (in separate terminals):**
    ```bash
    # CA Service
    ./bin/ca-service

    # ACME Server (Enable hybrid KEM)
    export GODEBUG=tls13kem=1
    ./bin/acme-server

    # Signing Service
    ./bin/signing-service

    # Transparency Log Service
    ./bin/transparency-log-service --storage-file /path/to/transparency.log --sth-key-file /path/to/sth_key.pem

    # Device Service (Set API Key)
    export DEVICE_API_KEY="your-secret-key"
    ./bin/device-service
    ```

## 8. API Endpoints

**(Note:** Base URLs depend on configured listen addresses and `SERVICE_HOST`.)*

**`ca-service` (Base URL assumed: `https://localhost:5000`)**

*   `POST /sign`
    *   Request: PEM-encoded CSR (`Content-Type: application/x-pem-file`)
    *   Response: PEM-encoded certificate chain (Issued Cert + CA Cert) (`Content-Type: application/x-pem-file`)
    *   Authentication: mTLS (client cert validated against CA and checked for revocation)
*   `POST /revoke-cert`
    *   Request: JSON `{"serial": "hex-serial-number"}` (`Content-Type: application/json`)
    *   Response: `200 OK` on success.
    *   Authentication: mTLS
*   `GET /crl`
    *   Response: DER-encoded CRL (`Content-Type: application/pkix-crl`)
*   `POST /ocsp`
    *   Request: DER-encoded OCSP request (`Content-Type: application/ocsp-request`)
    *   Response: DER-encoded OCSP response (`Content-Type: application/ocsp-response`)
*   `GET /healthz`, `GET /readyz`: Health checks.

**`acme-server` (Base URL assumed: `https://localhost:4000`)**

*   `GET /directory`
    *   Response: JSON ACME directory object.
*   `HEAD /acme/new-nonce` or `GET /acme/new-nonce`
    *   Response: `200 OK` with `Replay-Nonce` header.
*   `POST /acme/new-account`
    *   Request: JWS-signed payload (outer JWS uses new account key in `jwk` field). Payload often `{"termsOfServiceAgreed": true}`.
    *   Response: `201 Created` with `Location` header pointing to account URL. Body contains account details.
*   `POST /acme/new-order`
    *   Request: JWS-signed payload (outer JWS uses existing account key via `kid` field). Payload `{"identifiers": [{"type": "dns", "value": "example.com"}]}`.
    *   Response: `201 Created` with `Location` header pointing to order URL. Body contains order details (status, authorizations URL, finalize URL).
*   `POST /acme/challenge/{token}`
    *   Request: JWS-signed payload (outer JWS uses account key via `kid`). Payload often empty `{}` to signal readiness.
    *   Response: `200 OK`. Body contains challenge status update.
*   `POST /acme/finalize/{orderId}`
    *   Request: JWS-signed payload (outer JWS uses account key via `kid`). Payload `{"csr": "base64url-encoded-der-csr"}`.
    *   Response: `200 OK`. Body contains order status update and certificate URL.
*   `POST /acme/cert/{orderId}`
    *   Request: JWS-signed payload (outer JWS uses account key via `kid`). Payload often empty `{}`.
    *   Response: `200 OK`. Body contains PEM-encoded certificate chain (`Content-Type: application/x-pem-file`).
*   `POST /acme/revoke-cert`
    *   Request: JWS-signed payload (outer JWS uses account key via `kid`). Payload `{"certificate": "base64url-encoded-der-cert"}`.
    *   Response: `200 OK`.
*   `GET /healthz`, `GET /readyz`: Health checks.

**`signing-service` (Base URL assumed: `https://localhost:7000`)**

*   `POST /v1/accounts`
    *   Request: Empty body.
    *   Response: `201 Created`. JSON body with `accountID`, `apiKey`, `plan`, usage info.
*   `GET /v1/accounts/{accountID}`
    *   Response: JSON body with account usage info.
    *   Authentication: `X-API-Key` header.
*   `POST /v1/signatures`
    *   Request: JSON `SignRequest` (`{"artifactHash": "sha256:hexhash", "algorithm": "...", "sbom": {...}, "provenance": {...}}`) (`Content-Type: application/json`)
    *   Response: `200 OK`. JSON body `SignResponse` with `signature` and URLs.
    *   Authentication: `X-API-Key` header, rate limiting applied.
*   `GET /v1/log/{entryID}`
    *   Response: JSON `LogEntry`.
*   `GET /v1/log/{entryID}/sbom`
    *   Response: Raw SBOM content (`Content-Type: application/json`).
*   `GET /v1/log/{entryID}/provenance`
    *   Response: Raw provenance content (`Content-Type: application/json`).
*   `GET /v1/log?limit=N&offset=M`: List log entries.
*   `GET /metrics`: Prometheus metrics endpoint.
*   `GET /healthz`, `GET /readyz`: Health checks.

**`transparency-log-service` (Base URL assumed: `http://localhost:8085`)**

*   `POST /ct/v1/add-chain`
    *   Request: JSON `LogEntry` (`{"leaf_input": "base64", "chain": ["base64", ...]}`). Timestamp added by server.
    *   Response: `202 Accepted`.
*   `GET /ct/v1/get-sth`
    *   Response: JSON Signed Tree Head (`STH`).
*   `GET /ct/v1/get-entries?start=N&end=M`
    *   Response: JSON `EntriesResponse` (`{"entries": [...]}`).
*   `GET /ct/v1/get-proof-by-hash?hash=base64hash&tree_size=N`
    *   Response: JSON `ProofResponse` (`{"leaf_index": N, "audit_path": ["base64", ...]}`).
*   **Metrics:** `GET http://localhost:9095/metrics`

**`device-service` (Base URL assumed: `http://localhost:6000`)**

*   `POST /v1/devices`
    *   Request: JSON `{"csr": "base64url-encoded-der-csr"}` (`Content-Type: application/json`)
    *   Response: `201 Created`. JSON body with `deviceID` and `certChainPEM`.
    *   Authentication: `X-API-Key` header.

## 9. Client Authentication

*   **mTLS:** `ca-service`, `acme-server`, and `signing-service` support mutual TLS. Client certificates are verified against the CA specified by `CA_CERT_FILE` and checked against the CRL fetched from `CA_CRL_URL`.
*   **API Keys:** `signing-service` and `device-service` use the `X-API-Key` header for authentication.
*   **JWS:** `acme-server` uses JSON Web Signatures (JWS) according to RFC8555 to authenticate requests tied to an account key (`kid` header parameter) or a new key (`jwk` header parameter). It supports RSA, ECDSA, and EdDilithium2 signatures.

## 10. Revocation

*   **CRL:** The `ca-service` generates and serves a Certificate Revocation List (CRL) at `/crl`. Services configured with `TLS_CLIENT_AUTH=require_and_verify` (or similar) and a valid `CA_CRL_URL` will fetch this CRL periodically (cached for ~1 hour) and reject client certificates listed in it. The `verifyClientCertificate` function in `acme-server` and `signing-service` implements this logic.
*   **OCSP:** The `ca-service` provides an OCSP responder at `/ocsp`. The `acme-server` and `signing-service` fetch OCSP staples for their own TLS certificates from this endpoint.

## 11. Testing

*   **Unit Tests:** Some services have basic unit tests (e.g., `signing-service/main_test.go`). Run using `go test ./...` within the service directory.
*   **Integration Tests:** The `acme-server` includes an integration test for the PQ hybrid KEM handshake (`acme-server/pq_kem_handshake_test.go`). Run with:
    ```bash
    cd acme-server
    go test -tags integration -timeout 30s
    ```
*   **CI Tests:** The `.github/workflows/ci.yml` workflow runs tests for all services.
*   **ACME Server Testing Hooks:**
    *   `SKIP_DB=true`: Run without requiring a database connection.
    *   `SKIP_CA=true`: Run using a self-signed TLS certificate, bypassing the `ca-service`.
    *   `TLS_CLIENT_AUTH=none`: Disable mTLS requirement for easier testing.

## 12. CI/CD Pipeline

The GitHub Actions workflow defined in `.github/workflows/ci.yml` performs the following:

1.  **Checkout Code:** Clones the repository.
2.  **Set up Go:** Installs the specified Go version.
3.  **Cache Dependencies:** Caches Go modules for faster builds.
4.  **Install Dependencies:** Runs `go mod tidy` for each service.
5.  **Format & Vet:** Runs `go fmt` and `go vet` for each service.
6.  **Build Services:** Compiles binaries for all services into the `bin/` directory.
7.  **Run Tests:** Executes `go test ./...` for each service.
8.  **Generate SBOM:** Uses `anchore/sbom-action` (Syft) to generate a Software Bill of Materials (`sbom.json`) for the built binaries.
9.  **Attest Provenance:** Uses `actions/attest-build-provenance` to generate SLSA provenance (`attestations/sbom.intoto.jsonl`) for the SBOM.
10. **Upload Artifacts:** Uploads `sbom.json` and `attestations/*.intoto.jsonl` as workflow artifacts.

## 13. Security Considerations

*   **Key Management:** Private keys are critical. Use the `pkcs11` `KEYSTORE_TYPE` with a Hardware Security Module (HSM) for production environments. Filesystem storage (`fs`) is suitable for development/testing but requires careful permission management. Ensure key files (`*.pem`, `*.bin`) are not checked into version control.
*   **TLS Configuration:** Services are configured to use TLS 1.2 minimum. They prefer the X25519+MLKEM768 hybrid KEM for enhanced security against future quantum threats. Ensure `GODEBUG=tls13kem=1` is set if this is desired.
*   **Client Authentication:** Use strong authentication methods (mTLS, JWS with strong keys, secure API keys) as appropriate for each service.
*   **Revocation Checking:** Ensure CRL/OCSP checks are enabled and functioning correctly in production to prevent the use of compromised certificates.
*   **Input Validation:** Services implement basic input validation (e.g., body size limits, request format checks), but thorough validation is crucial.
*   **Database Security:** Secure the PostgreSQL database used by `acme-server` with strong credentials and appropriate network controls.
*   **API Key Security:** Protect API keys used by `signing-service` and `device-service`. Rotate keys periodically.
*   **Dependencies:** Keep Go modules updated to patch vulnerabilities (`go get -u ./... && go mod tidy`). The CI pipeline generates an SBOM to track dependencies.
*   **PQC Algorithm Choice:** EdDilithium2 and ML-KEM are current NIST PQC standard candidates/winners. Monitor the cryptographic landscape for updates or new recommendations.

This documentation provides a comprehensive guide to the Quantum-Safe PKI project. Refer to the source code for specific implementation details.
