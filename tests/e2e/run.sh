#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-ran:ci}"
CONTAINER="ran-e2e-$$"
SSH_PORT=12222
HTTP_PORT=18081
MYSQL_PORT=13307
METRICS_PORT=19550

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Starting ran container"
docker run -d \
  --name "$CONTAINER" \
  -e RAN_SSH=on \
  -e RAN_HTTP=on \
  -e RAN_MYSQL=on \
  -e RAN_SSH_ADDR=:2222 \
  -e RAN_HTTP_ADDR=:8081 \
  -e RAN_MYSQL_ADDR=:3307 \
  -e RAN_METRICS_ADDR=:9550 \
  -e RAN_LOG_FORMAT=json \
  -p "$SSH_PORT:2222" \
  -p "$HTTP_PORT:8081" \
  -p "$MYSQL_PORT:3307" \
  -p "$METRICS_PORT:9550" \
  "$IMAGE"

echo "==> Waiting for metrics server"
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:$METRICS_PORT/metrics" >/dev/null 2>&1; then
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "FAIL: metrics server not ready after 30s"
    docker logs "$CONTAINER"
    exit 1
  fi
  sleep 1
done

echo "==> Testing HTTP trap"
status=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/wp-login.php")
if [ "$status" != "200" ]; then
  echo "FAIL: HTTP GET /wp-login.php returned $status, expected 200"
  exit 1
fi

status=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -d "log=admin&pwd=test123" \
  "http://127.0.0.1:$HTTP_PORT/wp-login.php")
if [ "$status" != "200" ]; then
  echo "FAIL: HTTP POST /wp-login.php returned $status, expected 200"
  exit 1
fi

echo "==> Testing metrics endpoint"
metrics=$(curl -sf "http://127.0.0.1:$METRICS_PORT/metrics")
if ! echo "$metrics" | grep -q 'ran_connections_total'; then
  echo "FAIL: metrics missing ran_connections_total"
  exit 1
fi

echo "==> Verifying logs"
sleep 1
logs=$(docker logs "$CONTAINER" 2>&1)
if ! echo "$logs" | grep -q '"action":"auth_attempt"'; then
  echo "FAIL: logs missing auth_attempt"
  echo "$logs"
  exit 1
fi
if ! echo "$logs" | grep -q '"protocol":"http"'; then
  echo "FAIL: logs missing http protocol"
  echo "$logs"
  exit 1
fi

echo "==> All e2e tests passed"
