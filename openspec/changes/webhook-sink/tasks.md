## 1. Implementation

- [ ] 1.1 Config: `RAN_WEBHOOK_URL`, `RAN_WEBHOOK_CLASSES`, `RAN_WEBHOOK_TIMEOUT`, `RAN_WEBHOOK_HEADER`, validation, README rows (contract test)
- [ ] 1.2 `webhook.go`: Sink with bounded queue, one worker, no redirects, meta filter reused from CrowdSec
- [ ] 1.3 Compose the sensor sink so CrowdSec and webhook can both run (fan-out), shutdown drains within the shared budget
- [ ] 1.4 Metric `ran_webhook_total{result}`; README metrics list

## 2. Tests

- [ ] 2.1 `httptest` receiver: payload shape, no password, class filter, header
- [ ] 2.2 Slow receiver and full queue do not block `Submit`
- [ ] 2.3 Shutdown drain within the budget
- [ ] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
