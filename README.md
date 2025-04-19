# Quantum-Safe PKI as a Service

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
   ```