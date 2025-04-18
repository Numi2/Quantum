# Quantum-Safe PKI as a Service - Scaffold
+
## Overview
This repository contains initial scaffolding for a PQC-backed ACME server and a CA service in Go.
+
### Services
- `acme-server`: Implements ACME v2 directory, account, order, challenge, finalize, and cert endpoints with HTTP-01 challenge support.
- `ca-service`: Signs CSRs with a generated ECDSA P-256 CA root key and returns a PEM certificate chain.
+
## Prerequisites
- Go 1.20+
- Docker (optional)
+
## Running Services
+
1. Start the CA service (default port 5000):
```bash
cd ca-service
go run main.go
```
+
2. Start the ACME server (default port 4000):
```bash
cd acme-server
go run main.go
```
+
## Testing the Flow
+
- Retrieve ACME directory:
```bash
curl http://localhost:4000/directory
```
+
- Get a new nonce:
```bash
curl -I http://localhost:4000/acme/new-nonce
```
+
- Create a new account:
```bash
curl -X POST http://localhost:4000/acme/new-account -d '{}'
```
+
- Place a new order (identifier payload):
```bash
curl -X POST http://localhost:4000/acme/new-order -d '{"identifiers":[{"type":"dns","value":"example.com"}]}'
```
+
- Get challenge:
```bash
curl http://localhost:4000/acme/challenge/<token>
```
+
- Complete challenge:
```bash
curl -X POST http://localhost:4000/acme/challenge/<token>
```
+
- Finalize order (replace <csr-b64> with base64url CSR DER):
```bash
curl -X POST http://localhost:4000/acme/finalize/<orderID> -d '{"csr":"<csr-b64>"}'
```
+
- Fetch certificate:
```bash
curl http://localhost:4000/acme/cert/<orderID> -o cert.pem
```