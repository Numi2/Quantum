### Multi-stage Dockerfile for ACME Server

## Builder Stage
FROM golang:1.20-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o acme-server ./main.go

## Final Stage
FROM alpine:3.16
RUN apk add --no-cache ca-certificates
WORKDIR /root/
COPY --from=builder /app/acme-server ./acme-server
COPY --from=builder /app/migrations ./migrations
ENV DATABASE_URL=postgres://postgres:postgres@localhost:5432/acme?sslmode=disable
EXPOSE 4000
ENTRYPOINT ["/root/acme-server"]