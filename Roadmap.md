# Roadmap

## Step 1: Hardened Key Management

- Introduced a filesystem-based `KeyStore` (`ca-service/keystore.go` & `signing-service/keystore.go`) that persists private keys and certificates under a `KEY_DIR` (default `keys/`).
- Both the CA service and Signing service now:
  - Load their private keys on startup via `GetPrivateKey`; if missing, generate and store via `ImportPrivateKey`.
  - Load their X.509 certificates (for CA root and TLS) via `GetCertificate`; if missing, generate, sign, and store via `ImportCertificate`.
- Private keys are stored as PKCS#8 PEM (`<id>-key.pem`) with `0600` permissions. Certificates are stored as PEM (`<id>-cert.pem`) with `0644`.

### Next: Step 2 - Mutual‑TLS & Zero‑Trust Service Mesh
1. Completed: ACME ⇄ CA mutual‑TLS wiring
   - CA service and ACME server now exchange mTLS‑authenticated requests using keystore‑persisted certs.
   - ACME server fetches its server cert via a CSR and mTLS call to CA on first run, then serves ACME API over mTLS.
   - CA service enforces client‑cert validation (`RequireAndVerifyClientCert`) and serves its `/sign` API over HTTPS.
2. Completed: Step 3 - Revocation & Public‑Key Distribution (CRL)
   - CA `/revoke-cert` endpoint added (mTLS) and persists revocations to `revocations.json`.
   - ACME `/acme/revoke-cert` JWS‑verifies, extracts serial, and calls CA `/revoke-cert`.
   - CA `/crl` endpoint now emits a DER‑encoded X.509 CRL (`application/pkix-crl`).
3. Completed: Step 4 - OCSP Responder
   - CA `/ocsp` endpoint added (mTLS) to parse OCSP requests and return signed OCSP responses (DER, `application/ocsp-response`).
   - OCSP responses indicate `Good` or `Revoked` based on the revocation store.
   - Certificates issued by CA now include OCSPServer URLs under `OCSPServer` extension.
4. Completed: Step 5 - Client Revocation Checking & Stapling
   - ACME server and signing service now verify client certs against CRL in `VerifyPeerCertificate`.
   - Both TLS servers staple OCSP responses at startup and refresh staples every 12 hours.
   - Clients can retrieve revocation data via `CRL` and `OCSP` extensions in certificates.
5. Next: Step 6 - Observability & Logging
   - Instrument Prometheus metrics for all endpoints and expose `/metrics`.
   - Emit structured JSON logs including request IDs, JWS headers, and SLSA provenance data.
6. Next: Step 7 - Lights‑Out CI/CD & Regulation‑Aligned Compliance
   - Signing service now supports SBOM bundling and SLSA provenance via `/v1/signatures` payload and retrieval endpoints.
   - CLI updated to include `--sbom` and `--provenance` flags; SBOM & provenance are exposed via URLs in the response.
   - Provide sample GitHub Actions and Webhook integration for fully automated, zero‑touch signing pipelines.