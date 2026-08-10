# ber-encoding Specification

## Purpose
TBD - created by archiving change consolidate-ber-encoding. Update Purpose after archive.
## Requirements
### Requirement: BER length encoding
The `berLength` function SHALL encode an integer length into BER definite-form length octets. Lengths below 128 SHALL use short form (single byte). Lengths 128 and above SHALL use long form (0x80 | byte-count prefix followed by length bytes in big-endian).

#### Scenario: Short form length
- **WHEN** length is less than 128
- **THEN** the result is a single byte equal to the length value

#### Scenario: Long form length one byte
- **WHEN** length is between 128 and 255
- **THEN** the result is `[0x81, length]`

#### Scenario: Long form length two bytes
- **WHEN** length is between 256 and 65535
- **THEN** the result is `[0x82, high-byte, low-byte]`

### Requirement: BER integer encoding
The `berInteger` function SHALL encode an integer value as a BER INTEGER TLV with a caller-specified tag byte. The value SHALL be encoded in the minimum number of bytes using two's complement with a leading zero byte added when the high bit is set (to avoid sign ambiguity).

#### Scenario: Zero value
- **WHEN** value is 0 and tag is 0x02
- **THEN** the result is `[0x02, 0x01, 0x00]`

#### Scenario: Positive value without high bit
- **WHEN** value is 3 and tag is 0x02
- **THEN** the result is `[0x02, 0x01, 0x03]`

#### Scenario: Value with high bit set
- **WHEN** value is 128 and tag is 0x02
- **THEN** the result is `[0x02, 0x02, 0x00, 0x80]` (leading zero added)

#### Scenario: Custom tag
- **WHEN** value is 0 and tag is 0x0a
- **THEN** the result starts with `[0x0a, 0x01, 0x00]`

### Requirement: BER octet string encoding
The `berOctetString` function SHALL encode a byte slice as a BER OCTET STRING TLV with tag 0x04, the BER-encoded length, and the raw bytes as value.

#### Scenario: Non-empty octet string
- **WHEN** value is `[]byte("test")`
- **THEN** the result is `[0x04, 0x04, 't', 'e', 's', 't']`

#### Scenario: Empty octet string
- **WHEN** value is an empty byte slice
- **THEN** the result is `[0x04, 0x00]`

### Requirement: BER sequence encoding
The `berSequence` function SHALL encode a BER SEQUENCE TLV with a caller-specified tag byte. It SHALL accept variadic child byte slices, concatenate them to form the value, and prepend the tag and BER-encoded length.

#### Scenario: Single child
- **WHEN** tag is 0x30 and one child `[0x02, 0x01, 0x03]` is passed
- **THEN** the result is `[0x30, 0x03, 0x02, 0x01, 0x03]`

#### Scenario: Multiple children
- **WHEN** tag is 0x30 and two children are passed
- **THEN** the result contains both children concatenated as the sequence value

#### Scenario: No children
- **WHEN** tag is 0x30 and no children are passed
- **THEN** the result is `[0x30, 0x00]`

#### Scenario: Custom tag
- **WHEN** tag is 0x61 and children are passed
- **THEN** the result starts with `0x61`

