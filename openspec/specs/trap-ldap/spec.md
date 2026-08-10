## Purpose

LDAP honeypot trap that simulates an LDAP directory server to capture unauthorized bind attempts and credential harvesting.

## Requirements

### Requirement: LDAP bind credential capture
The LDAP trap SHALL listen on TCP, accept LDAP BindRequest messages (BER/ASN.1 encoded), extract the DN and password, log them, and respond with a BindResponse indicating invalidCredentials (result code 49).

#### Scenario: Simple bind credential capture
- **WHEN** a client sends a BindRequest with DN="cn=admin,dc=example,dc=com" and password="secret"
- **THEN** the trap SHALL log auth_attempt with username="cn=admin,dc=example,dc=com" and password="secret", alert CrowdSec, and respond with BindResponse resultCode=49

#### Scenario: Anonymous bind
- **WHEN** a client sends a BindRequest with empty DN and password
- **THEN** the trap SHALL log the anonymous bind attempt and respond with BindResponse resultCode=49

#### Scenario: Search request after bind failure
- **WHEN** a client sends a SearchRequest after a failed bind
- **THEN** the trap SHALL respond with SearchResultDone with insufficientAccessRights (result code 50)
