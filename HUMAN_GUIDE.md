# Production Readiness Guide for PQC/ACME/CA/Signing Service

This document provides step-by-step instructions for all the manual tasks required to complete the production deployment of the PQC‑hybrid signing platform. Deliverables are clearly marked at the end of each section.

## 1. HSM/KMS Integration
Purpose: Store all private keys (CA root, ACME server, signing service) in a secure, FIPS-certified HSM or cloud KMS.

1. Choose your HSM/KMS provider:
   - **Cloud KMS**: AWS KMS (asymmetric keys), Google Cloud KMS, Azure Key Vault.
   - **On‑prem HSM**: YubiHSM2, SoftHSM (for dev/test).
2. Provision or obtain a key:
   - If AWS KMS:
     ```bash
     aws kms create-key --description "PQC-Root-CA Key" --key-usage SIGN_VERIFY \  
       --customer-master-key-spec ECC_NIST_P256
     aws kms create-alias --alias-name alias/ca-root-pqc --target-key-id <KeyId>
     ```
   - If SoftHSM (dev):
     ```bash
     softhsm2-util --init-token --free --label "HSM-CA" --so-pin 0000 --pin 1111
     pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --keypairgen \  
       --key-type EC:secp256r1 --id 01 --label "ca-root"
     ```
3. Install and configure PKCS#11 middleware or vendor SDK:
   - Locate the shared library path (e.g. `/usr/lib/softhsm/libsofthsm2.so` or AWS PKCS#11 library).
   - Test with `pkcs11-tool` or AWS CLI for key listing.
4. Export HSM/KMS configuration to the services:
   - Set environment variables:
     ```ini
     KEYSTORE_TYPE=pkcs11
     PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
     PKCS11_TOKEN_LABEL=HSM-CA
     PKCS11_PIN=1111
     PRIVATE_KEY_ID=01
     ```
Deliverables:
   - HSM/KMS provider name and key identifier (ARN or slot ID).
   - Shared library path and sample environment variables.

## 2. Real TLS Certificates
Purpose: Use valid TLS certificates (public CA or internal PKI) for secure external endpoints.

1. Decide on CA:
   - **Let’s Encrypt** (free, automated) or **enterprise PKI** or **commercial CA**.
2. Obtain certificates:
   - With Certbot standalone:
     ```bash
     sudo certbot certonly --standalone -d acme.example.com
     sudo certbot certonly --standalone -d signing.example.com
     ```
3. Copy certs into keystore:
   ```bash
   mkdir -p ca-service/keys acme-server/keys signing-service/keys
   cp /etc/letsencrypt/live/acme.example.com/fullchain.pem acme-server/keys/acme-tls-cert.pem
   cp /etc/letsencrypt/live/acme.example.com/privkey.pem  acme-server/keys/acme-tls-key.pem
   # repeat for signing-service and CA if using real cert
   ```
4. Configure services:
   ```bash
   export TLS_CERT_FILE=acme-server/keys/acme-tls-cert.pem
   export TLS_KEY_FILE=acme-server/keys/acme-tls-key.pem
   ```
5. Test endpoint:
   ```bash
   curl https://acme.example.com/directory --cacert acme-server/keys/acme-tls-cert.pem
   ```
Deliverables:
   - PEM files for each service (`*-tls-cert.pem` and `*-tls-key.pem`).
   - Hostnames and proof of successful `curl`.

## 3. DNS & Networking
Purpose: Make services reachable via DNS and secure networks.

1. Add DNS A records:
   - `acme.example.com -> <Public IP>`
   - `signing.example.com -> <Public IP>`
   - `ca.example.com -> <Public IP>`
2. If testing locally, update `/etc/hosts`:
   ```ini
   127.0.0.1 acme.example.com signing.example.com ca.example.com
   ```
3. Open/forward firewall ports 443 and/or 5000/7000 as appropriate.
4. Verify name resolution:
   ```bash
   dig acme.example.com +short
   ping -c1 signing.example.com
   ```
Deliverables:
   - DNS zone file entries or screenshots.
   - Results of `dig` or `ping` commands.

## 4. Identity & Access Management (IAM)
Purpose: Enforce human/operator RBAC and secure API access beyond API keys.

1. Choose an OIDC provider:
   - Okta, Auth0, Azure AD, Keycloak, etc.
2. Register an application for each service:
   - Redirect URIs: e.g. `https://acme.example.com/oauth/callback`
3. Configure services to use OIDC:
   - Export env vars:
     ```ini
     OIDC_ISSUER=https://accounts.example.com
     OIDC_CLIENT_ID=<client-id>
     OIDC_CLIENT_SECRET=<client-secret>
     ```
4. Update code:
   - Replace `X-API-Key` middleware with OIDC token validation (JWT introspection or JWKS).
   - Apply RBAC rules (e.g. only users in group “CA-Admin” can revoke).
Deliverables:
   - OIDC metadata URL, client ID and secret.
   - Example config snippet and proof of successful login/auth.

## 5. SLSA Provenance Generation
Purpose: Embed supply‑chain metadata to meet SLSA and EU CRA requirements.

1. Integrate in your CI pipeline (e.g. GitHub Actions):
   ```yaml
   - name: Generate provenance
     run: |
       git clone https://github.com/sigstore/slsa-provenance-action.git
       # or use slsa-tools
       slsa-provenance-generator ...
     id: provenance
   - name: Upload provenance
     uses: actions/upload-artifact@v3
     with:
       name: provenance
       path: provenance.json
   ```
2. Pass provenance to CLI:
   ```bash
   ./cli/cli --artifact myapp.tar.gz \  
     --sbom myapp.sbom.json \  
     --provenance provenance.json
   ```
3. Retrieve via API:
   ```bash
   curl https://signing.example.com/v1/log/<entryID>/provenance
   ```
Deliverables:
   - CI pipeline snippet.
   - Sample provenance.json and proof of storage.

## 6. Service Mesh & Zero‑Trust with Istio
Purpose: Automate mTLS bootstrapping, enforce policies, gather telemetry.

1. Deploy to Kubernetes namespace:
   ```bash
   kubectl create namespace pqcpki
   kubectl label namespace pqcpki istio-injection=enabled
   ```
2. Deploy services to `pqcpki` namespace.
3. Apply Istio Gateway & VirtualService:
   See the sample YAML in Section 6 of `human.txt`.
4. Validate mTLS:
   ```bash
   istioctl authn tls-check acme-server.pqcpki
   ```
Deliverables:
   - `kubectl apply -f <gateway>.yaml` output.
   - `istioctl authn tls-check` report.

## 7. Compliance Artifacts
Purpose: Collect SBOMs, logs, and generate audit reports.

1. Configure Signing service to point logs to ELK/EFK:
   ```bash
   export LOG_ENDPOINT=https://logs.example.com/collector
   export LOG_FORMAT=json
   ```
2. Schedule periodic SBOM scans:
   ```bash
   syft acme-server/keys > acme-server.sbom.json
   ```
3. Archive revocations and audit logs monthly.
Deliverables:
   - ELK/Kibana dashboard URL.
   - SBOM JSON files.
   - Audit log archive.

---
By following each section in order and delivering the specified artifacts, you will equip the development team with everything needed to swap in automated key management, real certificates, DNS, IAM, and mesh policies—completing the hands‑on pieces required for full production readiness.