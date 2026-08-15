## 1. Config

- [x] 1.1 Replace `CrowdSecAPIKey` field with `CrowdSecMachineID` and `CrowdSecPassword` in Config struct
- [x] 1.2 Update env var parsing: `RAN_CROWDSEC_MACHINE_ID` and `RAN_CROWDSEC_PASSWORD` replace `RAN_CROWDSEC_API_KEY`
- [x] 1.3 Update validation: both `RAN_CROWDSEC_MACHINE_ID` and `RAN_CROWDSEC_PASSWORD` required when CrowdSec enabled
- [x] 1.4 Update config tests for new env vars and validation

## 2. Machine-Login and Token Management

- [x] 2.1 Add login types: `loginRequest{MachineID, Password}`, `loginResponse{Token, Expire}`
- [x] 2.2 Implement `login()` method: POST to `/v1/watchers/login`, parse JWT + expiry
- [x] 2.3 Replace `apiKey` field with `machineID`, `password`, `loginURL`, `token`, `tokenExpiry`, `mu sync.RWMutex`, `stopCh`, `wg sync.WaitGroup`
- [x] 2.4 Change `NewCrowdSec` signature to return `(*CrowdSecAlerter, error)`, perform eager login

## 3. Proactive Token Refresh

- [x] 3.1 Implement `refreshLoop()` goroutine: timer at 80% of token lifetime, exponential backoff on failure (10s→60s cap)
- [x] 3.2 Start `refreshLoop` in `NewCrowdSec`, register in WaitGroup

## 4. Push with JWT Auth

- [x] 4.1 Update `push()`: read token under RLock, set `Authorization: Bearer <token>` header
- [x] 4.2 Add 401-retry logic in `push()`: on 401, acquire write lock, double-check token, re-login if needed, retry once

## 5. Shutdown

- [x] 5.1 Update `Close()`: close `stopCh` to stop refreshLoop, close `ch` to stop worker, wait on WaitGroup with 5s timeout

## 6. Wiring

- [x] 6.1 Update `run.go`: pass `machineID` and `password` to `NewCrowdSec`, handle returned error

## 7. Tests

- [x] 7.1 Test successful login (mock `/v1/watchers/login` returning JWT + expiry)
- [x] 7.2 Test login failure (mock returning 403)
- [x] 7.3 Test push uses Bearer token header (not X-Api-Key)
- [x] 7.4 Test 401-retry: first push returns 401, re-login succeeds, retry succeeds
- [x] 7.5 Test token refresh: verify re-login is called before token expires
- [x] 7.6 Test graceful drain still works with new shutdown flow
- [x] 7.7 Update existing tests (channel overflow, failure metrics) for new constructor signature

## 8. Documentation

- [x] 8.1 Update README: CrowdSec section with new env vars, machine registration instructions
