# Quantum-Safe Public Key Infrastructure (PKI)

A set of Go-based services that implement a post-quantum cryptography (PQC) aware Public Key Infrastructure (PKI) and ACME (Automated Certificate Management Environment) server. This project demonstrates how to build a secure, extensible PKI using modern cryptographic techniques.

## Overview

This repository is structured as a monorepo of related services:

- **acme-server**: ACME v2 compliant server providing directory, nonce, account, order, challenge (HTTP-01), finalize, and certificate issuance endpoints. **This server now supports client authentication using JWS signatures based on the EdDilithium2 PQC algorithm (via CIRCL)** in addition to traditional ECDSA and RSA.
- **ca-service**: Certificate Authority service that signs Certificate Signing Requests (CSRs). It uses an ECDSA P-256 keypair for its own root certificate and TLS identity, but **uses an EdDilithium2 keypair (from the CIRCL library) to sign certificates issued via the `/sign` endpoint**. This demonstrates a hybrid approach where the CA's identity remains classical while issued artifacts use PQC signatures.

- **cli**: Command-line client for interacting with the ACME server, including account creation, order placement, and certificate retrieval.
- **device-service**: IoT device certificate issuance service.
- **signing-service**: Generic signing service for signing arbitrary payloads.
- **transparency-log-service**: Certificate Transparency (CT) log service that records issued certificates for auditing.

## Prerequisites

- Go 1.24.2 or newer  
- PostgreSQL (or CockroachDB) for ACME server state  
- `psql` client for running migrations  
- Docker (optional, for containerized deployment)

## Building the Services

All services can be built using Go's build command. The binaries will be placed in the `bin` directory:

```bash
# Create the bin directory
mkdir -p bin

# Build all services
go build -o bin/ca-service ./ca-service
go build -o bin/acme-server ./acme-server
go build -o bin/device-service ./device-service
go build -o bin/signing-service ./signing-service
go build -o bin/cli ./cli
go build -o bin/transparency-log-service ./transparency-log-service
```

The built binaries will be available in the `bin` directory with the following structure:
```
bin/
├── acme-server
├── ca-service
├── cli
├── device-service
├── signing-service
└── transparency-log-service
```

## Getting Started

1. Clone the repository  
   ```bash
   git clone https://github.com/your-org/your-repo.git
   cd your-repo
   ```

2. Set up environment variables  
   Create a `.env` file or export variables directly. Example:
   ```bash
   export DATABASE_URL="postgres://user:password@localhost:5432/acme?sslmode=disable"
   export PORT_ACME=4000
   export PORT_CA=5000
   ```

## Running the Services

Each service can be run independently. In separate terminals:

1. **CA Service**  
   ```bash
   cd ca-service
   go run main.go
   ```
   Default port: 5000

2. **ACME Server**  
   ```bash
   cd acme-server
   # Run database migrations
   psql "$DATABASE_URL" -f migrations/0001_create_acme_tables.up.sql
   # Run with experimental PQ KEM support (e.g., Kyber) enabled
   export GODEBUG=tls13kem=1 
   go run main.go
   ```
   Default port: 4000

3. **Other Services**  
   - **CLI**: `cd cli && go run main.go`  
   - **Device Service**: `cd device-service && go run main.go`  
   - **Signing Service**: `cd signing-service && go run main.go`  
   - **Transparency Log Service**: `cd transparency-log-service && go run main.go`

## Using the ACME Server

1. **Get Directory**  
   ```bash
   curl http://localhost:$PORT_ACME/directory
   ```

2. **Get Nonce**  
   ```bash
   curl -I http://localhost:$PORT_ACME/acme/new-nonce
   ```

3. **New Account**  
   ```bash
   curl -X POST http://localhost:$PORT_ACME/acme/new-account \
     -H "Content-Type: application/jose+json" \
     -d '{}'
   ```

4. **New Order**  
   ```bash
   curl -X POST http://localhost:$PORT_ACME/acme/new-order \
     -H "Content-Type: application/jose+json" \
     -d '{"identifiers":[{"type":"dns","value":"example.com"}]}'
   ```

5. **Get Challenge**  
   ```bash
   curl http://localhost:$PORT_ACME/acme/challenge/<token>
   ```

6. **Respond to Challenge**  
   ```bash
   curl -X POST http://localhost:$PORT_ACME/acme/challenge/<token> \
     -H "Content-Type: application/jose+json" \
     -d '{}'
   ```

7. **Finalize Order**  
   ```bash
   curl -X POST http://localhost:$PORT_ACME/acme/finalize/<orderID> \
     -H "Content-Type: application/jose+json" \
     -d '{"csr":"<csr-base64url>"}'
   ```

8. **Retrieve Certificate**  
   ```bash
   curl -O http://localhost:$PORT_ACME/acme/cert/<orderID>
   ```

## Advanced Configuration & Testing

### Testing Hooks
The ACME server supports several environment flags to simplify development and integration tests:

- `SKIP_DB=true`: skip database initialization (useful for in-memory or self-signed modes).
- `SKIP_CA=true`: bypass the external CA service and use a temporary self-signed TLS certificate.
- `TLS_CLIENT_AUTH=[none|request|require|verify_if_given|require_and_verify]`: configure Go TLS client authentication level.
- `KEY_DIR=<path>`: override the directory where TLS keys and certificates are stored.

Example: start the server without a database or CA, and no client‑auth:
```bash
SKIP_DB=true SKIP_CA=true TLS_CLIENT_AUTH=none KEY_DIR=keys_test \
  go run ./acme-server/main.go
```

### PQ Hybrid KEM Support
By default the server prefers a post‑quantum hybrid X25519+MLKEM key exchange on TLS 1.3 connections. To enable or disable it use Go's `GODEBUG`:
```bash
GODEBUG="tls13kem=1" go run ./acme-server/main.go   # enable hybrid KEM
GODEBUG="tls13kem=0" go run ./acme-server/main.go   # fall back to classical X25519 only
```

### Certificate Revocation via CRL
The server periodically fetches a Certificate Revocation List (CRL) from the CA (`CA_CRL_URL`) and rejects revoked client certificates during mutual TLS:

- CRL caches for up to 1 hour and refreshes automatically.
- CRL signature is verified against the CA certificate.
- Revoked certificates are rejected by serial number.

## Integration Tests
An integration test for the PQ hybrid KEM handshake is included under `acme-server/pq_kem_handshake_test.go`.
Run it with the `integration` build tag:
```bash
cd acme-server
go test -tags integration -timeout 30s
```

## Continuous Integration (CI)
The GitHub Actions workflow (`.github/workflows/ci.yml`) now:

- Builds and tests all services.
- Generates an SBOM (`sbom.json`) via Anchore/Syft.
- Attests SLSA provenance and writes a local Intoto predicate in `attestations/sbom.intoto.jsonl`.
- Uploads both the SBOM and provenance file as workflow artifacts.

This end‑to‑end pipeline ensures reproducible builds, provable supply chain integrity, and easy auditing.

## Licensing

This project is dual-licensed under:

- GNU Affero General Public License v3.0 (AGPL-3.0-or-later): see LICENSE-AGPL.md
- Commercial License: see LICENSE-COMMERCIAL.md

### License FAQ

Q: What license applies if I use the software in my own network service?  
A: Under the AGPL-3.0. If you run this software as a service, you must make your source code
   available under the AGPL. See LICENSE-AGPL.md.

Q: Can I embed or distribute this software in a proprietary product?  
A: Yes, by obtaining a commercial license from eMedic AS. Contact mail@siqn.org for terms.

Q: Who do I contact for commercial licensing?  
A: mail@siqn.org