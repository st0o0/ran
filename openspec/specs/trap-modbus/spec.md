## Purpose

Modbus TCP honeypot trap that simulates an industrial control system to capture function codes and register access attempts.

## Requirements

### Requirement: Modbus TCP function code capture
The Modbus trap SHALL listen on TCP, accept Modbus TCP frames (MBAP header + PDU), log the function code and register addresses, and respond with an exception response.

#### Scenario: Read Holding Registers (FC 03)
- **WHEN** a client sends a Modbus request with function code 0x03 (Read Holding Registers)
- **THEN** the trap SHALL log a payload event with function_code=3, starting_address, and quantity, alert CrowdSec, and respond with exception code 0x01 (Illegal Function)

#### Scenario: Write Single Register (FC 06)
- **WHEN** a client sends function code 0x06 with register address and value
- **THEN** the trap SHALL log the write attempt with address and value, and respond with exception code 0x01

#### Scenario: Invalid MBAP header
- **WHEN** a client sends data that does not conform to the MBAP header format
- **THEN** the trap SHALL close the connection
