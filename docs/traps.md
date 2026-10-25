# Traps

<!--@include: ./traps.generated.md-->

## Remote access

| Name | Port | Captures |
|---|---|---|
| `ssh` | `:2222` | Credentials (OpenSSH banner from the [banner profile](/configuration#banner-profiles); password and keyboard-interactive answers, and the SHA256 fingerprint and type of every offered public key, are logged as auth attempts and always rejected). Client identity: the client version string (`client_version`) and the HASSH of its KEXINIT (`hassh`) go to the log and the alert meta. Passwords never go to CrowdSec meta |
| `rdp` | `:3389` | Username (X.224 cookie extraction); one attempt per session. Alert meta adds `kind=connection_request` |
| `vnc` | `:5900` | Auth challenge/response (VNC Authentication); no password is recoverable from it without cracking the DES response. Alert meta: `kind=auth_response` |
| `telnet` | `:23`, `:2323` | Credentials (login/password prompts). IAC option negotiation is parsed: `DO` is answered with `WONT`, `WILL` with `DONT`, and IAC bytes never reach the username or password; a reported terminal type is logged (`terminal_type`, 64 bytes). Listens on both ports by default (`:2323` is the port Mirai-style botnets scan); see [Trap selection](/configuration#trap-selection) for multi-port |
| `ftp` | `:21` | Credentials (`USER` / `PASS`). Banner `220 FTP Server ready.`, lines up to 512 bytes. Every other command except `QUIT` gets `530` and is not logged |

## Web & proxy

| Name | Port | Captures |
|---|---|---|
| `http` | `:8081` | Every request is logged with method, path (no query string), `Host`, `User-Agent` and a header subset (values cut to 256 bytes, control characters replaced). Requests for known exploit and recon paths (`/.env`, `/.git/`, `/actuator`, `/cgi-bin/`, `/phpmyadmin`, traversal and so on) and requests carrying a JNDI lookup (`${jndi:`, also nested or percent encoded) in the request line or a header value are commands, so they classify as `attack`. Basic `Authorization` is captured as credentials, `POST` form logins (WordPress `/wp-login.php`, `/admin`, and a generic page for every other path) as before. A `POST`, `PUT` or `PATCH` body that is not a form login (JSON, XML) counts as payload bytes, read up to 16 KiB. Any other `GET`/`HEAD` stays a `probe`. Alert meta adds `path`, `method` and `user_agent`. Responses carry the `Server` and `X-Powered-By` headers of the [banner profile](/configuration#banner-profiles), identical on `http`, `https` and the fixtures (`Server: Apache/2.4.62` with `RAN_FINGERPRINT=fixed`). A `GET` or `HEAD` for one of a small set of fixture paths (see [HTTP fixtures](/configuration#http-fixtures)) gets a static product-like answer instead of the login page; classification is unchanged |
| `https` | `:8443` | The `http` trap behind TLS, with the same request handling and classification (exploit paths, JNDI, Basic auth and login forms are `attack`; a completed handshake without a request, a failed handshake and non-TLS bytes stay a `probe`). Uses two self-signed certificates (`CN=localhost`, ECDSA P-256 and RSA-2048), generated on first start and persisted at `RAN_HTTPS_CERT_PATH`. The ClientHello is fingerprinted before negotiation, so clients that fail the handshake are still logged (`tls client hello`): SNI, JA3 and JA4 (GREASE removed, lists capped, first TLS record only). Alert meta adds `sni`, `ja3` and `ja4` to the `http` meta. No client certificates. Accepts old clients: TLS 1.0 to 1.3 and every cipher suite Go implements, including RSA key exchange, 3DES, RC4 and CBC-SHA256 (see the threat notes) |
| `httpproxy` | `:8080` | `CONNECT host:port` and absolute-URI requests (`METHOD URL`, without userinfo, query and fragment) as commands, plus Basic `Proxy-Authorization` credentials. Requests with neither get `400` and stay a probe |
| `elasticsearch` | `:9200` | API requests with fake cluster responses (version, cluster and node name come from the [banner profile](/configuration#banner-profiles)). Classification: `GET`/`HEAD` without a body, and any `GET` to `/` or `/_cluster/health`, are probes. `POST`, `PUT`, `DELETE`, or `GET`/`HEAD` with a body on other paths are commands, recorded as `METHOD /path` only (no query string, no body; the body is read up to 4096 bytes). Other methods get `405` and are not recorded |

`http`, `https`, `docker`, `kubernetes`, `mcp` and `ipp` start a session per connection; `httpproxy` and `elasticsearch` start one per request.

## Containers & orchestration

| Name | Port | Captures |
|---|---|---|
| `docker` | `:2375` | Stub of the Docker Engine API (plain HTTP, no TLS). `GET /_ping`, `/version`, `/info`, `/containers/json` and `/images/json` (also with a `/v1.xx` prefix) get static answers and stay a `probe`. `POST /containers/create` and `POST /containers/{id}/exec` are commands recorded as `docker create image=... cmd=...` or `docker exec cmd=...` (JSON body read up to 16 KiB, image and command line cut to 256 bytes) and refused with `403`; nothing is pulled or executed. Any other state-changing method is recorded as `METHOD /path` and refused, unknown paths get `404`. Same JNDI check and header logging as `http`. Alert meta: `command`, `image`, `path`, `method`, `user_agent` |
| `kubernetes` | `:6443` | Stub of the Kubernetes API server and the kubelet API (plain HTTP, no TLS; set `RAN_KUBERNETES_ADDR=:6443,:10250` for the kubelet port). `GET /version`, `/api`, `/healthz`, `/livez` and `/readyz` get plausible answers and stay a `probe`; kubelet `/pods` and `/runningpods` answer `401`, every other path `403` as `system:anonymous`. `/run/`, `/exec/` and `/attach/` requests are commands (method, path and the `cmd`/`command` values of the query or form body, 256 bytes) and are refused. An `Authorization: Bearer` token is an auth attempt: only the first 8 hex characters of its SHA-256 are logged and sent as alert meta `token_hash`; the token itself is never stored. A token that is presented gets `401` instead of `403` |
| `mcp` | `:8000` | Static decoy of a Model Context Protocol server: JSON-RPC 2.0 over plain HTTP on `POST /mcp` and `POST /`. `initialize` (the `protocolVersion` is echoed only from a fixed list of three, anything else gets `2025-06-18`), `ping`, `notifications/initialized` (`202`, no body), `tools/list` (four inert bait tools: `read_file`, `list_directory`, `run_command`, `get_secrets`), `resources/list` and `prompts/list` (empty) stay a `probe`. `tools/call` is a command (`tools/call <tool> key=value ...`: tool name 64 bytes, at most 8 argument keys in sorted order, 128 bytes per string value, nested values not descended into, values of keys such as `password`, `token` or `secret` replaced by `***`) and an `attack`; it is answered with an `isError` result and nothing is executed. Alert meta: `tool` and `command`. Malformed JSON gets `-32700`, an invalid request `-32600`, an unknown method `-32601`; a batch of more than 16 messages (or an empty one) is rejected as a whole with `-32600`. `GET /sse` returns a finished event stream, `GET`/`DELETE` on `/mcp` and `/` get `405`. A request id is echoed only when it is an integer of at most 15 digits or a string of at most 64 characters from `A-Za-z0-9._:-`, else `null`. An `Authorization` or `X-API-Key` header is an auth attempt: only the first 8 hex characters of its SHA-256 are logged and sent as alert meta `token_hash`. `Mcp-Session-Id` is neither logged nor used. Exploit paths and JNDI strings are commands as in `http` |

`docker`, `kubernetes`, `mcp` and `ipp` reuse the request handling of `http` (sessions per connection, 16 KiB header and body limit, `claimed_client_ip` logging only, `Cookie` and `Authorization` never logged). The alert IP is always the socket peer.

## Databases

| Name | Port | Captures |
|---|---|---|
| `mysql` | `:3307` | Username and the client's auth response (the greeting reports the version of the [banner profile](/configuration#banner-profiles), `8.0.36` with `RAN_FINGERPRINT=fixed`, which also offers `mysql_clear_password` in the greeting; seeded mode uses the greeting of the profile generation and asks for the password with a switch; the value is plaintext only for clients that use the cleartext plugin, otherwise it is the client's scrambled response). Further attempts (see retries) use an authentication switch to `mysql_clear_password` |
| `postgres` | `:5432` | Credentials (cleartext password auth; after a rejected password the trap asks again on the same connection, up to the retry limit) |
| `mssql` | `:1433` | Credentials (TDS Login7 with password decode) |
| `oracle` | `:1521` | `USER` and `SERVICE_NAME` from the TNS CONNECT descriptor; no password. Alert meta adds `kind=connect` |
| `redis` | `:6379` | `AUTH` credentials + RESP and inline command logging |
| `memcached` | `:11211` | Command logging (text protocol) |
| `mongodb` | `:27017` | MongoDB wire protocol (`OP_MSG` and legacy `OP_QUERY`). `hello`/`isMaster`, `buildInfo` and `ping` are answered like a server that needs authentication and stay a `probe`. `saslStart` and `authenticate` are auth attempts: only the user name is kept (SCRAM `n=` attribute, PLAIN authcid, legacy `user`), never the proof, nonce or password, and the reply is `AuthenticationFailed`. Any other command is recorded by name only (alert meta `command`, 32 bytes) and answered with `Unauthorized`. Messages above 64 KiB close the connection |

## Mail

| Name | Port | Captures |
|---|---|---|
| `smtp` | `:25` | Credentials (AUTH LOGIN / PLAIN). The `220` greeting and the `EHLO` answer use the host name and software of the [banner profile](/configuration#banner-profiles) (`220 mx.localdomain ESMTP ready` with `RAN_FINGERPRINT=fixed`) |
| `pop3` | `:110` | Credentials (USER / PASS) |
| `imap` | `:143` | Credentials (LOGIN command); other commands except `CAPABILITY`, `NOOP` and `LOGOUT` are logged as commands |

## Directory & network

| Name | Port | Captures |
|---|---|---|
| `ldap` | `:389` | Credentials (simple bind DN + password) |
| `smb` | `:445` | SMB2 Session Setup: user, domain and workstation, taken only from an NTLMSSP Type 3 message. No password or hash is captured and no challenge is issued. Every Session Setup with a well-formed security buffer counts as an auth attempt (attack), whether or not it carries NTLMSSP |
| `socks5` | `:1080` | Username/password from clients that offer that method, or the `CONNECT` target of clients that offer no authentication |
| `irc` | `:6667` | `PASS` credentials (the username is the `NICK` seen so far) and other commands such as `JOIN`. `NICK`/`USER` registration alone is not logged |

## IoT & industrial

| Name | Port | Captures |
|---|---|---|
| `s7comm` | `:102` | S7comm over ISO on TCP (TPKT, COTP, S7). The COTP connection request, the setup communication request and SZL reads (module and component identification) are answered with a fixed, invented Siemens-like identity and stay a `probe`, as do read variable requests (answered with an S7 error), block-function userdata (list blocks, block info) and the read-clock userdata functions (time group, subfunctions 1 and 3). A first packet that is not TPKT (an HTTP request line, a TLS hello, an SSH banner, blank lines or another protocol) is cross-protocol noise: it is logged with a `sniffed_protocol` label and stays a `probe`; the same bytes after valid traffic, or a TPKT header with an impossible length, are `unknown` payload. COTP types are matched by the high nibble (connection request `0xE0` with any credit). Write variable (`write`), block download and upload, PLC control and stop (`control`) and any other function (`unknown`) are payload with an S7 error answer and make the session an `attack`. Alert meta: `kind` and, when an S7 job function was decoded, `function_code`. A TPKT length above 1024 bytes ends the session (`too_long`) before it is read; at most 64 packets per session |
| `enip` | `:44818` | EtherNet/IP encapsulation over TCP. `ListIdentity`, `ListServices`, `ListInterfaces` and `RegisterSession` (fixed session handle) are answered with a fixed, invented identity and stay a `probe`; `NOP` is ignored and `UnRegisterSession` ends the session. `SendRRData` and `SendUnitData` (`send_data`, with the CIP service code) and any unknown command (`unknown`) are payload, answered with an unsupported-command status, and make the session an `attack`. Alert meta: `kind`, `command_code` and, for `send_data`, `cip_service`. Data above 1024 bytes ends the session (`too_long`); at most 64 packets per session |
| `mqtt` | `:1883` | Credentials (CONNECT client ID + user/pass). Alert meta adds `kind=connect` |
| `modbus` | `:502` | Function codes with start address and quantity (capped at the Modbus maximum). Reads (1 to 4) and device identification (43) are fingerprinting and stay a `probe`; writes (5, 6, 15, 16, 22, 23) and unknown function codes are payload and make the session an `attack`. Alert meta adds `kind` (`write` or `unknown_function`) |
| `adb` | `:5555` | ADB CNXN system identity (AUTH token challenge). After the token the trap reads up to 8 more packets: an AUTH signature or public key is an auth attempt (only a SHA-256 is kept: `key_hash` for a public key, `signature_hash` for a signature), and OPEN with a `shell:` or `exec:` destination is a command (256 bytes) answered with CLSE. A first packet that is not CNXN is logged as an `adb_unknown` payload. Alert meta adds `kind` (`connect`, `auth` or `shell_command`) |
| `minecraft` | `:25565` | Handshake metadata + player names from login attempts. A server-list ping (status request) is a probe; only a login with a player name counts as payload. Alert meta adds `kind` (`status`, `login` or `handshake`) |

## Printers

| Name | Port | Captures |
|---|---|---|
| `pjl` | `:9100` | JetDirect raw printing with PJL. `@PJL INFO ID\|STATUS\|CONFIG\|VARIABLES\|USTATUS`, `@PJL USTATUS` and `@PJL ECHO` get fixed answers with an invented printer identity (`@PJL ECHO <text>` repeats at most 32 bytes of the text, printable ASCII only, everything else is dropped; `@PJL INFO FILESYS` returns one static volume) and stay a `probe`, as do job framing commands (`JOB`, `EOJ`, `ENTER`, `COMMENT`, `INQUIRE`) and UEL sequences (also split across reads). Lines end with CR, LF or CRLF. A first chunk that looks like HTTP, TLS, SMB, SSH or RDP is cross-protocol noise: it is logged with its `sniffed_protocol` label, gets no answer and stays a `probe`. Filesystem commands (`FSDIR`, `FSUPLOAD`, `FSDOWNLOAD`, `FSDELETE`, `FSMKDIR`, ...) are commands (`fs_command`) answered with `FILEERROR=3`; `SET`, `DEFAULT`, `INITIALIZE`, `RESET`, `OPMSG` and similar are commands (`set`) answered with `?`; any other `@PJL` verb is a command (`other`). Everything that is not a PJL line (PCL, PostScript, binary) is print data: it is counted as payload bytes and only its length, a SHA-256 prefix (16 hex characters) and a printable prefix of at most 64 bytes (secret-like `key=value` pairs hidden) are logged; the data itself is never stored. Alert meta: `kind` and `command` (scrubbed) for commands, `kind`, `data_bytes` and `data_hash` for print data |
| `ipp` | `:631` | IPP over HTTP (CUPS style, plain HTTP). `Get-Printer-Attributes`, `CUPS-Get-Printers` and `CUPS-Get-Default` get a valid IPP answer with fixed attributes (nothing from the request, not even the `Host` header, is reflected), `Get-Jobs` and `Validate-Job` get a successful answer without attributes, `Get-Job-Attributes` gets `client-error-not-found`, and all of them stay a `probe` (a JNDI string in such a request makes it a command with `kind` `other`). The printer advertises IPP 1.0, 1.1, 2.0, 2.1 and 2.2 and a static `printer-up-time`. `Print-Job`, `Create-Job`, `Send-Document` and `Send-URI` (`print_job`, refused with `client-error-not-authorized`) and every other operation (`other`, refused with `server-error-operation-not-supported`) are commands recorded with the operation name, the job name (64 bytes, scrubbed) and the document size only; document bytes are never stored. A `GET`/`HEAD`/`OPTIONS` request gets a static page and stays a `probe`; any other method, or a `POST` that is not IPP, is a command (`other`). Alert meta: `path`, `method`, `user_agent`, `command`, `kind`, `operation`, `document_bytes` and, with a job name, `job_name` |

## Catch-all & banner

These two traps have no default port: they only listen where you tell them to
(see [Catch-all and banner traps](/configuration#catch-all-and-banner-traps)), and `ran`
refuses to start with either enabled and no address.

| Name | Port | Captures |
|---|---|---|
| `catchall` | none (`RAN_CATCHALL_ADDR`) | Accepts a TCP connection on any port you route to it, waits up to 3 seconds (never longer than the session timeout) for the first bytes and captures at most 256 of them. What is logged depends on `RAN_LOG_PASSWORDS`: `off` (default) logs only the label, the byte count and `sha256_prefix` (first 8 hex characters of the SHA-256), `mask` adds `hex` and `text` as `*** (<length>)`, `on` logs the bytes as hex and printable text. The alert meta never carries bytes. The bytes are labeled `tls`, `http`, `smb`, `ssh`, `rdp` or `unknown` (`sniffed_protocol`, also in the alert meta). It never sends anything back. Any received byte makes the session an `attack`; a connect that stays silent is a `probe` |
| `banner` | none (`RAN_BANNER_SERVICES`) | Sends a configured banner on connect, then reads client lines (512 bytes) and logs them as commands (values of `Authorization`, `Proxy-Authorization` and `Cookie` lines and the arguments of credential verbs like `PASS` or `AUTH` follow `RAN_LOG_PASSWORDS`; other content of a custom protocol is logged as sent), so the session is an `attack`. A connect without data is a `probe`. The configured service name only appears in the log and the alert meta (`service`) |

## UDP

| Name | Port | Captures |
|---|---|---|
| `dns` | `:53` | Query domains + types (responds REFUSED) |
| `snmp` | `:161` | Community string and version (v1/v2c `GetRequest` and `GetNextRequest`) |
| `sip` | `:5060` | Method, `From`/`To` headers and the Digest `username`. The Digest response is not captured, and the credentials counter stays 0 for SIP |
| `ntp` | `:123` | Version and mode of mode 3 client packets; answers with a Kiss-o'-Death `DENY`. `monlist` (mode 7) and other modes only log a `parse_failed` error |

UDP source addresses are spoofable, so UDP traps log and count metrics only.
They never raise CrowdSec alerts (the UDP constructors take no alerter at all).
Inbound packets are rate limited per source and globally (see [Limits](/configuration#limits)).
Every UDP packet that passes the rate limiter is its own session with `connect`
and `disconnect` log lines; probe summarization applies to TCP only.
