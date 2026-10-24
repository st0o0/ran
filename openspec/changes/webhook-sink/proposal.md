## Why

Operators without CrowdSec, or who want an extra notification, have only the JSON log. OpenCanary and Beelzebub offer webhooks and brokers. A single generic webhook is cheap and keeps the sensor model (it forwards classified events, nothing is decided by rán).

## What Changes

- New `RAN_WEBHOOK_URL` (HTTPS or HTTP URL), optional `RAN_WEBHOOK_CLASSES` (default `attack,scan`) and `RAN_WEBHOOK_TIMEOUT` (default `5s`). The event JSON has the same fields as the CrowdSec event meta (class, protocol, source IP, dest port, counters, bounded meta) and never contains passwords or tokens.
- A second `Sink` behind the existing sensor, with its own bounded queue (256), cooldown shared with the alert pipeline, and metrics `ran_webhook_total{result}` (`sent`, `failed`, `dropped`) with a fixed label set.
- SSRF care: the URL is fixed by the operator at startup; redirects are not followed; a private or loopback target is allowed (operators often run local relays) but logged at startup.
- Works with CrowdSec on or off.

## Capabilities

### New Capabilities

- `webhook-sink`.

## Impact

- New `internal/alert/webhook.go`, config parsing and validation, metrics, README, tests with `httptest`.

## Non-goals

- No templating, no authentication schemes beyond a static header value from `RAN_WEBHOOK_HEADER`, no retries beyond one attempt per batch, no brokers (RabbitMQ, Kafka).
- No UDP events.
