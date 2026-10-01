# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /ran ./cmd/ran

FROM scratch
COPY --from=build /ran /ran
COPY LICENSE.md /LICENSE.md

EXPOSE 21 23 25 53/udp 110 123/udp 143 161/udp 389 445 502 1080 1433 1521 1883 2222 3307 3389 5060/udp 5432 5555 5900 6379 6667 8080 8081 9200 9550 11211 25565

HEALTHCHECK --interval=30s --timeout=10s \
           --start-period=15s --retries=3 \
  CMD ["/ran", "healthcheck"]

ENTRYPOINT ["/ran"]
