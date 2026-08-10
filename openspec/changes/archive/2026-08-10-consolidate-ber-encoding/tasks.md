## 1. Create shared BER encoding module

- [x] 1.1 Create `internal/trap/ber.go` with `berLength`, `berInteger`, `berOctetString`, `berSequence` using unified signatures from the design (tag parameters, `int64` values, `[]byte` octet strings, variadic children)
- [x] 1.2 Create `internal/trap/ber_test.go` covering all spec scenarios: short/long form lengths, zero/positive/high-bit integers, custom tags, empty/non-empty octet strings, single/multiple/no children sequences

## 2. Migrate LDAP to shared functions

- [x] 2.1 Remove `berEncodeLength`, `berEncodeInteger`, `berEncodeOctetString`, `berEncodeSequence` from `ldap.go`
- [x] 2.2 Update `ldap.go` call sites: rename to `berLength`/`berInteger`/`berOctetString`/`berSequence`, convert string args to `[]byte`
- [x] 2.3 Update `ldap_test.go` helpers to use new function names and signatures

## 3. Migrate SNMP to shared functions

- [x] 3.1 Remove `berLength`, `berInteger`, `berOctetString`, `berSequence` from `snmp.go`
- [x] 3.2 Update `snmp.go` call sites: add tag arguments (`0x02` for integers, `0x30` for sequences), change `int` to `int64` where needed
- [x] 3.3 Update `snmp_test.go` call sites to match new signatures

## 4. Verify

- [x] 4.1 Run `go build ./...` to confirm compilation
- [x] 4.2 Run `go test ./internal/trap/...` to confirm all existing and new tests pass
