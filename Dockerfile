FROM golang:1.26.5-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /ran ./cmd/ran

FROM scratch

COPY --from=build /ran /ran
COPY LICENSE.md /LICENSE.md

EXPOSE 21 23 25 53/udp 110 123/udp 143 161/udp 389 445 502 1080 1433 1521 1883 2222 3307 3389 5060/udp 5432 5900 6379 6667 8080 8081 9200 9550 11211

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["/ran", "healthcheck"]

ENTRYPOINT ["/ran"]
