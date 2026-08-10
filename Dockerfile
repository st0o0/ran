FROM golang:1.26.1-alpine AS build

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

EXPOSE 2222 8081 3307 9550

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["/ran", "healthcheck"]

ENTRYPOINT ["/ran"]
