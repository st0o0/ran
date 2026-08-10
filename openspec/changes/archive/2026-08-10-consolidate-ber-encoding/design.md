## Context

Both `ldap.go` and `snmp.go` in `internal/trap/` implement BER encoding functions independently. The implementations are nearly identical but differ in two ways:

1. **Length encoding**: LDAP uses `encoding/binary.BigEndian` for multi-byte lengths; SNMP uses manual byte shifting. Both produce the same output.
2. **Signature differences**: LDAP's `berEncodeInteger` takes a `tag byte` parameter and `int64` value; SNMP's `berInteger` hardcodes tag `0x02` and takes `int`. LDAP's `berEncodeSequence` takes a `tag byte` and variadic `children ...[]byte`; SNMP's `berSequence` hardcodes tag `0x30` and takes a single `[]byte`.

Decoding functions differ fundamentally: LDAP reads from `io.Reader` streams, SNMP parses `[]byte` slices with offset tracking. These stay in their respective files.

## Goals / Non-Goals

**Goals:**
- Single BER encoding implementation in `internal/trap/ber.go`
- Unified API that serves both LDAP and SNMP callers
- Unit tests for the shared functions in `ber_test.go`

**Non-Goals:**
- Consolidating BER decoding (incompatible APIs by design)
- Supporting negative integers or multi-byte tags (not needed by current callers)
- Creating a general-purpose BER library

## Decisions

### Adopt LDAP-style signatures with tag parameters

The shared functions use the LDAP convention of accepting a `tag byte` parameter for `berInteger` and `berSequence`, since LDAP needs multiple tag values (e.g., `0x02` for INTEGER, `0x0a` for ENUMERATED; `0x30` for SEQUENCE, `0x61`/`0x65` for application-specific). SNMP call sites add the tag argument (`0x02` / `0x30`).

Alternative: Keep SNMP-style hardcoded tags and add separate functions for LDAP's custom tags. Rejected because it increases the API surface without benefit.

### Use `berSequence(tag, children ...[]byte)` variadic signature

LDAP passes multiple children; SNMP passes a single pre-concatenated `[]byte`. The variadic form handles both: SNMP wraps its single slice as one argument. This is the LDAP-style `berEncodeSequence` signature.

### Use `int64` for integer values, `[]byte` for octet strings

LDAP uses `int64`; SNMP uses `int`. Adopting `int64` avoids truncation. For octet strings, LDAP uses `string` and SNMP uses `[]byte`. Adopting `[]byte` is more general; LDAP call sites convert with `[]byte(s)`.

### Use LDAP-style length encoding with `encoding/binary`

The LDAP implementation of `berLength` using `binary.BigEndian.PutUint32` correctly handles lengths up to 4 bytes and is clearer than the SNMP version (which only handles up to 2 bytes).

## Risks / Trade-offs

- **Caller churn**: LDAP callers rename `berEncode*` to `ber*` and SNMP callers add tag parameters. Mitigated by same-package scope (no exported API changes) and existing test coverage for both protocols.
- **Signature mismatch for octet strings**: Changing LDAP from `string` to `[]byte` adds `[]byte()` conversions at call sites. Minor verbosity, no runtime cost.
