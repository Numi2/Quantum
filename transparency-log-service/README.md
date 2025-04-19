# Transparency Log Service

This service provides an append-only transparency log for certificate chains,
following CT-style auditing interfaces.

## Features
- CT endpoints: `/ct/v1/add-chain`, `/ct/v1/get-sth`, `/ct/v1/get-entries`, `/ct/v1/get-proof-by-hash`
- Append-only JSON storage (file-based)
- Structured JSON logging (zap)
- Prometheus metrics
- Merkle tree construction, Signed Tree Head (STH) generation, and inclusion proofs

## Usage
```
go run main.go --addr :8085 --metrics-addr :9095 --storage-file transparency.log
```
- `addr`: HTTP server address for CT API
- `metrics-addr`: HTTP server address for Prometheus metrics (`/metrics`)
- `storage-file`: path to append-only log file

## Next Steps
- Persistent database backend (PostgreSQL)
- Integration tests
- Post-quantum or hybrid STH signing support