# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
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
