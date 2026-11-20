# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /ran ./cmd/ran
# Data directory for the SSH host key and the HTTPS certificate, owned by the runtime user (scratch has no mkdir/chown).
RUN mkdir -p /rootfs/data && chown 65532:65532 /rootfs/data && chmod 0700 /rootfs/data

FROM scratch
# CA bundle for HTTPS CrowdSec LAPI URLs (the golang alpine image ships it).
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /rootfs/data /data
COPY --from=build /ran /ran
COPY LICENSE /

USER 65532:65532
VOLUME ["/data"]

EXPOSE 21 23 25 53/udp 102 110 123/udp 143 161/udp 389 445 502 631 1080 1433 1521 1883 2222 2323 2375 3307 3389 5060/udp 5432 5555 5900 6379 6443 6667 8000 8080 8081 8443 9100 9200 9550 11211 25565 27017 44818

HEALTHCHECK --interval=30s --timeout=10s \
           --start-period=15s --retries=3 \
  CMD ["/ran", "healthcheck"]

ENTRYPOINT ["/ran"]
