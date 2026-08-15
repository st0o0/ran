## MODIFIED Requirements

### Requirement: CrowdSec LAPI push
The worker SHALL POST alerts to `{RAN_CROWDSEC_URL}/v1/alerts` with a JWT token in the `Authorization: Bearer <token>` header, obtained via machine-login. On a 401 response, the worker SHALL attempt one inline re-login and retry the push. If the retry also fails, the alert SHALL be dropped with a warning log and failure metric.

#### Scenario: Successful push
- **WHEN** the LAPI is reachable and the token is valid
- **THEN** the alert is accepted and `ran_crowdsec_alerts_total{protocol,status="success"}` is incremented

#### Scenario: LAPI unreachable
- **WHEN** the LAPI returns an error or is unreachable
- **THEN** a warning is logged, `ran_crowdsec_alerts_total{protocol,status="failure"}` is incremented, and the worker continues

#### Scenario: Token expired (401 response)
- **WHEN** the LAPI returns 401 Unauthorized
- **THEN** the worker SHALL attempt one re-login and retry the push
- **AND** if the retry succeeds, `ran_crowdsec_alerts_total{protocol,status="success"}` is incremented
- **AND** if the retry fails, the alert is dropped with a warning log and failure metric

## ADDED Requirements

### Requirement: Machine-login authentication
The alerter SHALL authenticate to CrowdSec LAPI via `POST /v1/watchers/login` with `machine_id` and `password` fields. The LAPI returns a JSON response with `token` (JWT string) and `expire` (RFC3339 timestamp). The alerter SHALL store both and use the token for all subsequent API calls.

#### Scenario: Successful login
- **WHEN** `POST /v1/watchers/login` is called with valid credentials
- **THEN** the alerter stores the returned JWT token and its expiry time

#### Scenario: Invalid credentials
- **WHEN** `POST /v1/watchers/login` returns a non-2xx status
- **THEN** the login SHALL return an error

#### Scenario: LAPI unreachable during login
- **WHEN** `POST /v1/watchers/login` fails due to network error
- **THEN** the login SHALL return an error

### Requirement: Eager login on startup
`NewCrowdSec()` SHALL perform a synchronous login during construction. If the login fails, `NewCrowdSec()` SHALL return an error, preventing ran from starting with invalid CrowdSec credentials.

#### Scenario: Startup with valid credentials
- **WHEN** `NewCrowdSec()` is called and login succeeds
- **THEN** a `CrowdSecAlerter` is returned with a valid token

#### Scenario: Startup with invalid credentials
- **WHEN** `NewCrowdSec()` is called and login fails
- **THEN** an error is returned and no alerter is created

### Requirement: Proactive token refresh
The alerter SHALL run a background goroutine that refreshes the JWT token at 80% of its lifetime. On refresh failure, the goroutine SHALL retry with exponential backoff (starting at 10s, doubling, capped at 60s) until either the refresh succeeds or the alerter is closed.

#### Scenario: Normal refresh
- **WHEN** the token lifetime is 1 hour
- **THEN** the refresh goroutine attempts re-login at 48 minutes (80%)

#### Scenario: Refresh failure with retry
- **WHEN** the LAPI is temporarily unreachable during refresh
- **THEN** the goroutine retries after 10s, then 20s, then 40s, then 60s, capped at 60s

#### Scenario: Refresh failure logging
- **WHEN** a token refresh attempt fails
- **THEN** a warning-level log is emitted with the error

#### Scenario: Shutdown during refresh
- **WHEN** `Close()` is called while the refresh goroutine is waiting
- **THEN** the refresh goroutine exits promptly

### Requirement: Graceful shutdown
On shutdown, the alerter SHALL stop the refresh goroutine and drain remaining alerts from the channel (up to 5 seconds) before exiting.

#### Scenario: Shutdown stops refresh and drains alerts
- **WHEN** `Close()` is called with 3 alerts in the channel
- **THEN** the refresh goroutine stops and the worker attempts to push all 3 alerts before exiting
