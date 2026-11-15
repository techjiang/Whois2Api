# syntax=docker/dockerfile:1

# --- build -------------------------------------------------------------------
FROM golang:1.23-alpine AS build
WORKDIR /src

# Dependencies first so source edits do not re-download modules.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags "-s -w \
        -X github.com/techjiang/Whois2Api/internal/version.Version=${VERSION} \
        -X github.com/techjiang/Whois2Api/internal/version.Commit=${COMMIT} \
        -X github.com/techjiang/Whois2Api/internal/version.Date=${BUILD_DATE}" \
      -o /out/whois2api ./cmd/whois2api

# --- runtime -----------------------------------------------------------------
FROM alpine:3.20

# ca-certificates for RDAP over TLS; tzdata so log timestamps are interpretable.
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -g 10001 -S whois2api \
 && adduser  -u 10001 -S -G whois2api -H -s /sbin/nologin whois2api \
 && mkdir -p /data \
 && chown whois2api:whois2api /data

COPY --from=build /out/whois2api /usr/local/bin/whois2api

# The data directory is the entire persistent state: one file inside it.
VOLUME ["/data"]
ENV W2A_DATA_DIR=/data \
    W2A_LISTEN=:8080

USER whois2api
EXPOSE 8080

# Use the binary's own healthcheck so the image needs no curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/whois2api", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/whois2api"]
