## ADDED Requirements

### Requirement: Webhook delivery
When `RAN_WEBHOOK_URL` is set, classified events of the classes in `RAN_WEBHOOK_CLASSES` SHALL be POSTed as JSON to that URL. The payload SHALL NOT contain passwords, tokens or other keys dropped by the CrowdSec meta filter.

#### Scenario: Attack event
- **WHEN** an SSH password attempt is classified `attack`
- **THEN** one JSON event with class, protocol, source IP and bounded meta is posted and no password field is present

#### Scenario: Filtered class
- **WHEN** a `probe` event occurs and the classes are `attack,scan`
- **THEN** nothing is posted

### Requirement: Bounded and non-blocking
The sink SHALL use a bounded queue of 256 events, SHALL drop events when it is full and SHALL NOT block trap sessions. Redirects SHALL NOT be followed and the request timeout SHALL be `RAN_WEBHOOK_TIMEOUT`.

#### Scenario: Slow receiver
- **WHEN** the receiver does not answer
- **THEN** sessions are unaffected, requests time out and `ran_webhook_total{result="failed"}` increases

#### Scenario: Queue full
- **WHEN** more than 256 events are waiting
- **THEN** the excess events are dropped and `ran_webhook_total{result="dropped"}` increases

### Requirement: Validation
The URL SHALL be validated at startup (scheme `http` or `https`, host present) and an invalid value SHALL make the configuration invalid.

#### Scenario: Bad scheme
- **WHEN** `RAN_WEBHOOK_URL=ftp://x/y`
- **THEN** `ran check-config` exits 1 and names the variable
