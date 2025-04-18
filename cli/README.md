# CLI Client for Signing Service

## Overview
Command-line tool to compute a SHA-256 hash of an artifact and request a PQC-hybrid signature.

## Building
```bash
cd cli
go build -o sign-cli main.go
```

## Usage
```bash
./sign-cli --artifact path/to/file --server http://localhost:7000 --algorithm ECDSA+Dilithium
```
Outputs signature and transparency log URL.