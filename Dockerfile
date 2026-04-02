FROM golang:1.21-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /build

# Copy go module files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY *.go ./
COPY templates/ ./templates/
COPY policies.yaml ./

# Build static binary with CGo (required for pg_query_go)
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -linkmode external -extldflags '-static'" \
    -o faultwall .

# ──────────────────────────────────────────
FROM alpine:3.19

WORKDIR /app

# Install CA certs for TLS connections
RUN apk add --no-cache ca-certificates tzdata

# Copy binary and templates
COPY --from=builder /build/faultwall /app/faultwall
COPY templates/ /app/templates/
COPY assets/logos/ /app/assets/logos/

# Non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 5433 8080

ENTRYPOINT ["/app/faultwall"]
