## MODIFIED Requirements

### Requirement: Docker healthcheck
The Dockerfile SHALL define `HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 CMD ["/ran", "healthcheck"]`.

#### Scenario: Container health
- **WHEN** the container is running with metrics enabled
- **THEN** Docker reports the container as healthy after the start period

#### Scenario: Start period grace
- **WHEN** the container has just started and traps are still binding
- **THEN** Docker SHALL not mark the container as unhealthy during the first 45 seconds
