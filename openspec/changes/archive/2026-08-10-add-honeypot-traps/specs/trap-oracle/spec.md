## ADDED Requirements

### Requirement: Oracle TNS credential capture
The Oracle trap SHALL listen on TCP, accept a TNS Connect packet, respond with Accept, then capture authentication data from subsequent packets, and respond with a Refuse/error.

#### Scenario: TNS connect and credential capture
- **WHEN** a client sends a TNS Connect packet with service name and user
- **THEN** the trap SHALL log the connection details including service name and username, alert CrowdSec, and respond with a TNS Refuse packet with "ORA-01017: invalid username/password"

#### Scenario: TNS connect parsing
- **WHEN** a client sends a TNS Connect packet
- **THEN** the trap SHALL extract and log the connect descriptor including HOST, PORT, SERVICE_NAME, and USER fields
