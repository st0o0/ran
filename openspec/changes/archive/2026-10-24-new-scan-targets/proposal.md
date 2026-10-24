## Why

Several services are scanned heavily for exploitation and cryptominer campaigns, but rán has no trap for them: the Docker Engine API (`2375`), the Kubernetes API and kubelet (`6443`, `10250`) and MongoDB (`27017`). Telnet is also scanned on `2323` by Mirai-style botnets, and the default is only `:23`. Each missing target is a blind spot that the breadth-based scan detection also never sees.

## What Changes

- New trap `docker` (default `:2375`): HTTP/JSON stub of the Engine API (`/version`, `/_ping`, `/containers/json`, `/images/json`, `/info`). Container create and exec requests are recorded as commands (image, command line, bounded) and refused.
- New trap `kubernetes` (default `:6443`, also usable for `:10250`): HTTP stub answering `/version`, `/api`, `/healthz`, kubelet `/pods` and `/run` with plausible responses and `401`/`403` for the rest. A request carrying a bearer token is an auth attempt (token never stored, only a hash prefix).
- New trap `mongodb` (default `:27017`): `OP_MSG`/`OP_QUERY` handshake (`isMaster`/`hello`, `buildInfo`, `listDatabases`) with an authentication-required answer; `saslStart` is an auth attempt (username only).
- `telnet` default listen address becomes `:23,:2323` (if one of them cannot bind, behavior follows the existing multi-port rules).
- All traps use the shared TCP skeleton, registered in `config.DefaultPorts`, `config.ValidTraps` and `trap.Registry`, documented in the README, with fuzz targets for the two binary parsers where applicable.

## Capabilities

### New Capabilities

- `trap-docker`, `trap-kubernetes`, `trap-mongodb`.

### Modified Capabilities

- `config-traps-list`: three traps added, telnet default addresses.

## Impact

- New `docker.go`, `kubernetes.go`, `mongodb.go` (+ tests), `config.go`, `registry.go`, README trap tables and `RAN_<PROTO>_*` rows, Dockerfile ports if listed. Contract tests (`registry_test.go`, `contract_test.go`) must pass.

## Non-goals

- No real container, pod or database semantics: every state-changing request is refused.
- No outbound connections, image pulls or command execution.
- No TLS in this change (Kubernetes normally speaks TLS; it follows `tls-traps` later).
