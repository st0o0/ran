## Purpose

Multi-stage Docker build producing a minimal scratch-based container image for the ran honeypot binary.

## Requirements

### Requirement: Multi-stage Dockerfile
The Dockerfile SHALL use a multi-stage build: Go builder stage on `golang:<version>-alpine` with `CGO_ENABLED=0`, runtime stage on `scratch`.

#### Scenario: Build output
- **WHEN** the image is built
- **THEN** the final image contains only the `ran` binary, LICENSE, and NOTICE files

### Requirement: Image size
The final image SHALL be less than 20MB.

#### Scenario: Size check
- **WHEN** the image is built for linux/amd64
- **THEN** the compressed image size is under 20MB

### Requirement: Version injection
The build SHALL accept a `VERSION` build arg and inject it via `-ldflags="-s -w -X main.version=${VERSION}"`.

#### Scenario: Version in binary
- **WHEN** `docker build --build-arg VERSION=0.1.0 .` is run
- **THEN** `ran version` inside the container prints `0.1.0`

### Requirement: Docker healthcheck
The Dockerfile SHALL define `HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 CMD ["/ran", "healthcheck"]`.

#### Scenario: Container health
- **WHEN** the container is running with metrics enabled
- **THEN** Docker reports the container as healthy after the start period

#### Scenario: Start period grace
- **WHEN** the container has just started and traps are still binding
- **THEN** Docker SHALL not mark the container as unhealthy during the first 45 seconds

### Requirement: Build flags
The Go binary SHALL be compiled with `-trimpath` and `-ldflags="-s -w"` to strip debug info and paths.

#### Scenario: Minimal binary
- **WHEN** the binary is compiled
- **THEN** it contains no debug symbols or build paths
