## Context

The CrowdSec LAPI POST /v1/alerts endpoint expects an array of alert objects. Each alert must include an `events` field (JSON array — can be empty `[]` but not absent or `null`). The current `csAlert` struct has no `Events` field, so the marshalled payload omits it entirely, causing a 500 rejection during validation. Additionally, `source.scope` uses lowercase `"ip"` while CrowdSec uses `"Ip"` (capital I).

The `Alerter` interface currently passes only `ip` and `protocol`, but every trap has richer context available at the call site (usernames, passwords, commands, domains). This data maps directly to CrowdSec's event `meta` array.

## Goals / Non-Goals

**Goals:**
- Fix the 500 by including a valid `events` array in the alert payload
- Enrich events with trap-specific metadata (usernames, passwords, commands, domains)
- Fix scope casing to match CrowdSec's canonical format
- Keep the interface change minimal — one additional parameter

**Non-Goals:**
- Batching multiple events per alert (each trap trigger = one alert with one event)
- Changing the channel/worker architecture
- Adding new CrowdSec API endpoints (scenarios, decisions API, etc.)
- Storing or indexing metadata locally

## Decisions

### 1. Metadata as `map[string]string`

The `Alerter` interface gains one parameter: `meta map[string]string`.

```go
type Alerter interface {
    Alert(ctx context.Context, ip string, protocol string, meta map[string]string)
    Close()
}
```

**Why not typed struct?** A typed `AlertInfo` struct with fields like `Username`, `Password`, `Command` would require updating the struct every time a new trap type with new metadata is added. `map[string]string` is extensible without interface changes. CrowdSec's event meta is itself key-value pairs, so the mapping is direct.

**Why not `[]slog.Attr`?** While traps already build `slog.Attr` slices, reusing them would couple the alert system to slog internals. A plain map is simpler and has no external dependency.

Traps that have no metadata (e.g. memcached) pass `nil` — this is zero-allocation and `push()` handles it by creating an event with an empty meta array.

### 2. CrowdSec event types

```go
type csEvent struct {
    Timestamp string   `json:"timestamp"`
    Meta      []csMeta `json:"meta"`
}

type csMeta struct {
    Key   string `json:"key"`
    Value string `json:"value"`
}
```

Each alert gets exactly one event. The `push()` function converts `map[string]string` into `[]csMeta` sorted by key for deterministic output. The event timestamp matches the alert's `start_at`.

### 3. Scope casing fix

Change `"ip"` to `"Ip"` in both `csSource.Scope` and `csDecision.Scope`. This matches CrowdSec's internal constant `types.Ip = "Ip"`. The casing matters for decision matching in CrowdSec's bouncer chain.

### 4. Metadata key conventions

Traps use consistent keys across protocols:

| Key | Used by | Example |
|-----|---------|---------|
| `username` | ssh, http, mysql, mssql, ftp, imap, pop3, irc, ldap, rdp, smb, mqtt, oracle | `"root"` |
| `password` | ssh, http, mysql, ftp, imap, pop3, irc, ldap, redis, mqtt | `"admin123"` |
| `domain` | dns, smb | `"example.com"` |
| `command` | elasticsearch, modbus | `"GET /_cluster/health"` |
| `client_id` | mqtt | `"paho-client"` |
| `service_name` | oracle | `"ORCL"` |
| `qtype` | dns | `"A"` |
| `workstation` | smb | `"WIN-PC01"` |
| `version` | ntp | `"4"` |
| `mode` | ntp | `"3"` |

## Risks / Trade-offs

- **[Breaking interface change]** → All ~20 trap call sites and all tests need updating. Mitigated by the fact that this is a single-parameter addition and `NoopAlerter` simply ignores the map.
- **[Credentials in CrowdSec events]** → Usernames and passwords end up in CrowdSec's database. This is acceptable because: (a) these are attacker-supplied credentials against a honeypot, not real user credentials; (b) they have forensic/intelligence value for threat analysis; (c) CrowdSec's own scenarios do the same with community blocklists.
- **[Map allocation per alert]** → Each alert creates a small map. At the volumes a honeypot sees, this is negligible. Traps with no metadata pass `nil` (zero alloc).
