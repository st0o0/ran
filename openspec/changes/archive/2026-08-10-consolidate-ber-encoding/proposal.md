## Why

The `internal/trap` package contains duplicate BER (Basic Encoding Rules) encoding functions in `ldap.go` and `snmp.go`. Both files independently implement `berLength`, `berInteger`, `berOctetString`, and `berSequence` with slightly different signatures but identical logic. Consolidating these into a shared `ber.go` eliminates duplication and provides a single tested implementation.

## What Changes

- Extract shared BER encoding functions (`berLength`, `berInteger`, `berOctetString`, `berSequence`) into `internal/trap/ber.go`
- Unify function signatures across LDAP and SNMP callers
- Update `ldap.go` to use shared encoding functions (remove `berEncodeLength`, `berEncodeInteger`, `berEncodeOctetString`, `berEncodeSequence`)
- Update `snmp.go` to use shared encoding functions (remove `berLength`, `berInteger`, `berOctetString`, `berSequence`)
- Add `ber_test.go` with unit tests for the shared encoding functions
- Keep BER decoding functions in their respective files (LDAP uses `io.Reader` streams, SNMP uses offset-based `[]byte` slices — incompatible APIs)

## Capabilities

### New Capabilities

- `ber-encoding`: Shared BER encoding primitives for length, integer, octet string, and sequence encoding used by protocol traps

### Modified Capabilities

<!-- No existing spec-level requirements are changing. LDAP and SNMP traps retain identical external behavior. -->

## Impact

- `internal/trap/ldap.go`: Remove 4 encoding functions, update call sites to use shared names
- `internal/trap/snmp.go`: Remove 4 encoding functions, update call sites to use shared names
- `internal/trap/ldap_test.go`: Update helper calls to new function names
- `internal/trap/snmp_test.go`: No changes needed (already uses `berLength`/`berInteger`/etc.)
- New files: `internal/trap/ber.go`, `internal/trap/ber_test.go`
