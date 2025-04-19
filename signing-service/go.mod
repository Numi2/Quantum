module pqcpki/signing-service

go 1.20

require (
   github.com/cloudflare/circl v1.5.0 // for PQC Dilithium2
   go.uber.org/zap v1.21.0          // for structured logging
   github.com/prometheus/client_golang v1.14.0 // metrics
   github.com/ThalesGroup/crypto11 v1.4.1
)