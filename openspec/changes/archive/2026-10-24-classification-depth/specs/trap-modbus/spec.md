## ADDED Requirements

### Requirement: Read versus write classification
The Modbus trap SHALL treat read requests (function codes 1, 2, 3, 4) and device identification (43) as fingerprinting that stays a `probe` (logged with action `probe`, no payload, no alert), and write requests (5, 6, 15, 16, 22, 23) and unknown function codes as payload counted as `attack`. Every request is answered with exception 0x01.

#### Scenario: Read holding registers
- **WHEN** a client sends function code 3
- **THEN** a `probe` event is logged with start address and quantity and the session stays a `probe`

#### Scenario: Write single register
- **WHEN** a client sends function code 6
- **THEN** a payload is logged with address and value, an alert is raised and the session is `attack`

#### Scenario: Read then write
- **WHEN** a client sends function code 3 and then function code 6 on one connection
- **THEN** the session is an `attack`

#### Scenario: Quantity bound
- **WHEN** a request declares a quantity above the Modbus maximum (2000 for function codes 1 and 2, 125 for 3, 4 and the read part of 23, 1968 for 15, 123 for 16, 121 for the write part of 23)
- **THEN** the value is logged cut to the maximum and no allocation depends on it
