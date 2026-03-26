FROM golang:1.21-alpine AS builder

WORKDIR /build

# Copy go module files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY *.go ./

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o faultwall .

# ──────────────────────────────────────────
FROM alpine:3.19

WORKDIR /app

# Install CA certs for TLS connections
RUN apk add --no-cache ca-certificates tzdata

# Copy binary and templates
COPY --from=builder /build/faultwall /app/faultwall
COPY templates/ /app/templates/

# Non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 8080

ENV PORT=8080

ENTRYPOINT ["/app/faultwall"]
