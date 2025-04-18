# IoT Device Provisioning Service

## Overview
This service provides a REST API for automated provisioning of device certificates. Devices submit a CSR and receive a signed certificate chain.

## Prerequisites
- Go 1.20+
- Running CA Service (e.g., from `ca-service/` on port 5000)
- Set environment variable `DEVICE_API_KEY` to a shared secret for API access

## Running the Service
```bash
cd device-service
export DEVICE_API_KEY=your-secret-key
# optional: export CA_SIGN_URL=http://localhost:5000/sign
go run main.go
```

The service listens on port 6000.

## API

### Provision a Device Certificate
**POST** `/v1/devices`
Headers:
  `X-API-Key: <your secret>`
Body (JSON):
```json
{ "csr": "<base64url-encoded CSR DER>" }
```
Response (201 Created):
```json
{
  "deviceID": "<generated-device-id>",
  "certChainPEM": "-----BEGIN CERTIFICATE-----..."
}
```

`certChainPEM` contains the leaf and CA certs in PEM format.

## Next Steps
- Add persistent storage for device records
- Integrate PQC key generation and hybrid certificates
- Support mutual-TLS authentication for devices