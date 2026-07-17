# ─────────────────────────────────────────
# Stage 1: Build Go binary
# ─────────────────────────────────────────
FROM golang:1.26.4-bookworm AS builder

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /build/loxtu-go ./cmd/server/

# ─────────────────────────────────────────
# Stage 2: Minimal runtime
# ─────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/loxtu-go .
COPY --from=builder /build/web ./web
COPY --from=builder /build/migrations ./migrations
EXPOSE ${LOXTU_PORT:-8880}

CMD ["./loxtu-go"]