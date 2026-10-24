## ADDED Requirements

### Requirement: Read versus write classification
The Modbus trap SHALL treat read requests (function codes 1, 2, 3, 4) and device identification (43) as fingerprinting that stays a `probe`, and write requests (5, 6, 15, 16, 22, 23) and unknown function codes as payload counted as `attack`.

#### Scenario: Read holding registers
- **WHEN** a client sends function code 3
- **THEN** a `probe` event is logged with start address and quantity and the session stays a `probe`

#### Scenario: Write single register
- **WHEN** a client sends function code 6
- **THEN** a payload is logged with address and value, an alert is raised and the session is `attack`

#### Scenario: Quantity bound
- **WHEN** a read request declares a quantity above the Modbus maximum
- **THEN** the value is logged cut to the maximum and no allocation depends on it
