## 1. Health endpoint handler

- [x] 1.1 Add `/healthz` handler to the metrics mux in `cmd/ran/main.go` — accepts version (string), start time (time.Time), and trap names ([]string) via closure; returns JSON `{"status":"ok","version":"...","uptime":"...","traps":[...]}`  with Content-Type `application/json`
- [x] 1.2 Track process start time in `main()` before starting the metrics server

## 2. Healthcheck subcommand

- [x] 2.1 Rewrite `cmd/ran/health.go` to HTTP GET `http://<metricsAddr>/healthz` with 2s timeout instead of TCP dial; exit 0 on 200, exit 1 otherwise

## 3. Dockerfile

- [x] 3.1 Update HEALTHCHECK directive: `--interval=30s --timeout=10s --start-period=15s --retries=3`

## 4. Tests

- [x] 4.1 Unit test for `/healthz` handler — assert 200, valid JSON, correct fields (status, version, uptime, traps)
- [x] 4.2 Unit test for healthcheck subcommand — test against a real httptest server returning 200 and one returning 503
