## ADDED Requirements

### Requirement: Elasticsearch HTTP API trap
The Elasticsearch trap SHALL listen on TCP as an HTTP server, respond to common Elasticsearch API endpoints with fake cluster information, and log all requests.

#### Scenario: Root endpoint
- **WHEN** a client sends `GET /`
- **THEN** the trap SHALL respond with a JSON body containing fake cluster name, version, and tagline, and log the request

#### Scenario: Search/index request
- **WHEN** a client sends `GET /_search` or `PUT /index/_doc/1`
- **THEN** the trap SHALL log the request method, path, and body, and respond with a plausible JSON error

#### Scenario: Cluster health
- **WHEN** a client sends `GET /_cluster/health`
- **THEN** the trap SHALL respond with a JSON body showing status "green" and log the request
