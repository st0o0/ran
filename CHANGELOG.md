# Changelog

## [0.5.0](https://github.com/st0o0/ran/compare/v0.4.0...v0.5.0) (2026-10-31)


### ⚠ BREAKING CHANGES

* require RAN_PROXY_TRUSTED when the PROXY protocol is enabled

### Features

* add catchall and banner traps for ports without a named trap ([1a4fe07](https://github.com/st0o0/ran/commit/1a4fe07f8f0e2268b906cf254b904dec6414945e))
* add docker, kubernetes and mongodb traps and listen on telnet port 2323 by default ([67ce58f](https://github.com/st0o0/ran/commit/67ce58ffb721f8736a281496810d63fe3c06cdab))
* add https trap with self-signed certificate and JA3/JA4 ClientHello fingerprints ([b974447](https://github.com/st0o0/ran/commit/b974447685ec57f522edf3187d50953557d2a7d6))
* add mcp decoy trap that records tool calls as attacks ([883c4b0](https://github.com/st0o0/ran/commit/883c4b0435970f2324ccdbbe1603d98a5caad4ec))
* add opt-in shun and repeat cooldown to quiet persistent sources ([7642183](https://github.com/st0o0/ran/commit/7642183da3eb9938085df7e3998e715dcde920ce))
* add RAN_IGNORE_IPS to keep trusted sources out of alerts, scan tracking and probe summaries ([9695654](https://github.com/st0o0/ran/commit/9695654740d5513a9512a0cfd6ae4dc26e01081a))
* add s7comm, enip, pjl and ipp traps ([a8917bc](https://github.com/st0o0/ran/commit/a8917bcc45b8df017b52814a4998a3d6ba4dc450))
* add scenario-based config builder page to the documentation site ([47674e1](https://github.com/st0o0/ran/commit/47674e1084cf23117d4140933f8d2569921e3d44))
* cap alert and repeat cooldowns at one year and add shared builder cases for list and bool validation ([82dd369](https://github.com/st0o0/ran/commit/82dd369185850e6fbe462fe7c085eb45561dff8b))
* capture SSH public-key and keyboard-interactive attempts with client version and HASSH ([8f96a89](https://github.com/st0o0/ran/commit/8f96a89fd4449eebd6552d382785273b6d770ee3))
* classify Modbus reads and writes, capture ADB shell opens, strip Telnet IAC, retry MySQL and Postgres auth and detect port scans ([eba765f](https://github.com/st0o0/ran/commit/eba765f2b353e9b015300a48ba39fa439f2c1a20))
* generate a settings register and builder rule cases from the configuration loader ([fa215be](https://github.com/st0o0/ran/commit/fa215beaec58bd1d5f17cbd363a4a75af88e9479))
* log every HTTP request and classify exploit paths, JNDI strings and Basic auth ([0d6f6f3](https://github.com/st0o0/ran/commit/0d6f6f398fcd5f929393d704999bb9e4d3e719b6))
* require RAN_PROXY_TRUSTED when the PROXY protocol is enabled ([37e11cf](https://github.com/st0o0/ran/commit/37e11cf7b24eb0eb46ecb32a5fa8d600e84b9cb2))
* seeded banner profiles per instance and kind meta for single-request traps ([cb3690c](https://github.com/st0o0/ran/commit/cb3690c636119df385a25d80a44b9ab673dfe995))
* select PROXY protocol per trap so proxied and direct traps can coexist ([598b06a](https://github.com/st0o0/ran/commit/598b06ae6ce5f9170de23faf7dcd88c536be17be))
* serve static scanner fixtures on http and https with optional operator fixtures ([a4df107](https://github.com/st0o0/ran/commit/a4df107b67309876fac464f2dd67d4043bc65f84))
* ship the example CrowdSec profile with a subcommand and a real CrowdSec integration test ([d1ab755](https://github.com/st0o0/ran/commit/d1ab755da6b7d9f9a48d0056d7f656effa193477))


### Bug Fixes

* accept legacy TLS clients, write cert atomically and align JA4 with the spec ([407d933](https://github.com/st0o0/ran/commit/407d933a83412c261744c4bf5c3a7cc97d8af835))
* align builder and register bounds with the loader and warn about ineffective cooldown settings ([ffb3149](https://github.com/st0o0/ran/commit/ffb3149411ecdaf8084ab5d190d7d824de78f7fa))
* **ci:** tolerate spurious fuzz deadline races in smoke job ([a70d43f](https://github.com/st0o0/ran/commit/a70d43fa0ce6fe118de2769b2034dbc95b85a312))
* correct builder compose and env output, validate more settings and rewrite the getting-started guide ([e7eab85](https://github.com/st0o0/ran/commit/e7eab85c95f33d1a1e99e88bf29e1c1fa2221f41))
* do not record the MySQL auth scramble as an empty-password credential ([97e82e1](https://github.com/st0o0/ran/commit/97e82e19dabd8191f737dc0643663183bfb5d4ec))
* drop false word-count bound in FuzzParseDockerBody ([46449a8](https://github.com/st0o0/ran/commit/46449a82f6b6260b3a858aed0587e667b60a9d4f))
* gate catchall payload logging on RAN_LOG_PASSWORDS and redact auth headers in banner lines ([2539344](https://github.com/st0o0/ran/commit/2539344225824b3a4fdcff187914305a72a84be2))
* guard MySQL and Postgres retries against repeated passwords and old clients and end auth delays at the session deadline ([64f7a03](https://github.com/st0o0/ran/commit/64f7a031a09d1a3804f1ce4ac01f1d907e652425))
* harden HTTP exploit path matching against bypasses and false positives ([653d790](https://github.com/st0o0/ran/commit/653d790c2007f72c224700ee68ac911cde2b67c2))
* harden proxy and retry tests against timing flakes and document NAT trust pitfalls ([cee630d](https://github.com/st0o0/ran/commit/cee630d65aa685c8bc659b728a21a4245da5ccc3))
* keep SASL PLAIN passwords out of MongoDB logs and alerts and treat OPTIONS as read-only ([c5f8eca](https://github.com/st0o0/ran/commit/c5f8eca3cb15fbe9da85e7eebe64a6a4b9c97103))
* keep scanner noise a probe on s7comm and pjl, cap IPP document sizes and remove fingerprint tells ([38a6816](https://github.com/st0o0/ran/commit/38a6816af181ec84de0d285c070f89b4eb84b4f5))
* log shun summaries outside the table lock and fail startup when shun cannot be enforced ([22f02f6](https://github.com/st0o0/ran/commit/22f02f68ccc6965123b7a2ce50cb4d093910a265))
* make wasm_exec.js copy writable and truncate JSON decode errors in fixture parser ([b87ff46](https://github.com/st0o0/ran/commit/b87ff463580ee2d37812fb3aaa28cedeb7635ecc))
* pin banner selection with a golden test and align SSH, MySQL and Elasticsearch banners with their profiles ([289353a](https://github.com/st0o0/ran/commit/289353a5930535eb1e50fccb866820babbc9b085))
* record failed keyboard-interactive attempts and bound SSH log values ([3e7c850](https://github.com/st0o0/ran/commit/3e7c850269527730619b4dafecfe1021718ddc83))
* reject percent signs and duplicate keys in operator fixtures ([22e6746](https://github.com/st0o0/ran/commit/22e6746a24aa5247dfbb38254d01c30d8e19a858))
* revert the offender entry when an alert push fails and keep active shuns when the table evicts ([c9955da](https://github.com/st0o0/ran/commit/c9955da558dd54eadccc03b2fb799a9d9952fe3d))
* scrub secrets from stub trap commands and bound the MCP request id ([644287c](https://github.com/st0o0/ran/commit/644287c10fe67c03b8ff10bde66edc534bbc6ee8))
* skip peer address parsing on accept when shun is off ([20a2964](https://github.com/st0o0/ran/commit/20a2964867deab06df7ff0ce8635ad3599af8d93))
* strip = from MCP argument key names in summary to satisfy fuzz bound ([badef98](https://github.com/st0o0/ran/commit/badef981837d66776e3b30889da1efc32a0a0311))
* warn on very wide ignore ranges, cap the ignore list and extend its tests ([f3bcf04](https://github.com/st0o0/ran/commit/f3bcf04bf8847b2a51c3138b95eff041d92478d8))


### Documentation

* add competitor comparison and collapse reference sections in README ([d4cf80f](https://github.com/st0o0/ran/commit/d4cf80fd024ac9108e627140ade54a3906716110))
* add config-builder openspec change ([cde6e53](https://github.com/st0o0/ran/commit/cde6e53b032d154009d9a506095d4584f39bec5d))
* add crowdsec-integration openspec change ([f0c40d5](https://github.com/st0o0/ran/commit/f0c40d58431ce6dcb40f5775996e94bc0905efb6))
* add docs-site openspec change and record the VitePress layout decision ([cefab82](https://github.com/st0o0/ran/commit/cefab827bbbcfc264dc133fcbaf14ae169c26705))
* add proxy-protocol-per-trap and quiet-repeat-offenders openspec changes from operator log analysis ([4e3198c](https://github.com/st0o0/ran/commit/4e3198cced091b50bce9fae7b1bdce16125332dd))
* add todo.md and openspec changes for the roadmap ([0d843fd](https://github.com/st0o0/ran/commit/0d843fd442b4a8148dc73e3dcc71e20e4ea350a2))
* add VitePress documentation site with generated trap table and docs build in CI ([2f56cc5](https://github.com/st0o0/ran/commit/2f56cc5a9a9bb022a74c929d090c20ca7fca99fc))
* defer webhook-sink in todo.md ([77b1dfd](https://github.com/st0o0/ran/commit/77b1dfd05596e6681c9942bcebb123908f75fd80))
* mark shipped changes as archived in the roadmap ([6b990ec](https://github.com/st0o0/ran/commit/6b990ec5c3ff261395feab817e9533afa20a36d3))
* record docs site evaluation and correct the CrowdSec plan in todo.md ([e9450ed](https://github.com/st0o0/ran/commit/e9450ed23e570c00f9f6a8f13121660ca22355a6))
* shrink the README to pitch and quick start now that the site carries the reference ([c5cd007](https://github.com/st0o0/ran/commit/c5cd007e6964c88927a8a09d1dcd08932dc25a66))
* update todo.md and add docs site evaluation ([174f0b0](https://github.com/st0o0/ran/commit/174f0b0d6abfc20e7e17ec194c727b8f8f35a36a))


### Refactoring

* derive the UDP trap set for the docs generator from config.UDPTraps and test it against the implementations ([c55c4a0](https://github.com/st0o0/ran/commit/c55c4a09608607b7068f24a280229e978ebb9192))
* **docs:** replace builder scenarios with composable proxy and CrowdSec sections ([f8cc5f1](https://github.com/st0o0/ran/commit/f8cc5f1a683944cc56dfe22e5949fa9f86cb58ec))
* drive builder duration and list rules from register flags instead of variable names ([092b16d](https://github.com/st0o0/ran/commit/092b16dfbf3eb6e6f1fbae576555767c81e559bb))
* let the CrowdSec sink own the offender table and expose it through a shun gate ([35ad3e3](https://github.com/st0o0/ran/commit/35ad3e3f5d0419c03caecf65d57547054bb1580a))
* run the sensor config check in the docs builder as WebAssembly and reject duplicate listen addresses in Load ([e59054f](https://github.com/st0o0/ran/commit/e59054fcee64dd8c2b5389fe111ab942f81b535f))

## [0.4.0](https://github.com/st0o0/ran/compare/v0.3.8...v0.4.0) (2026-10-24)


### ⚠ BREAKING CHANGES

* push decision-less sensor alerts classified attack/probe/scan and add shared TCP trap skeleton

### Features

* push decision-less sensor alerts classified attack/probe/scan and add shared TCP trap skeleton ([821539b](https://github.com/st0o0/ran/commit/821539b3c159429075d26ff730a9b8987e10ee30))


### Bug Fixes

* validate durations, allow unlimited SSH retries, downgrade unbanned scans, default cooldown 1h ([c4ff95f](https://github.com/st0o0/ran/commit/c4ff95f7053a66138860b9704818bf422be86bf0))


### Documentation

* add AGENTS.md contributor and agent notes ([0143013](https://github.com/st0o0/ran/commit/0143013127f2fdb12e9e65c1b901e4b5647ad231))
* document config validation, SSH limits, scan downgrade and 1h alert cooldown ([bfe3a62](https://github.com/st0o0/ran/commit/bfe3a621d38fcca964b67e5ddd9e3de3a3b424b6))
* **openspec:** sync sensor and trap lifecycle specs and archive changes ([541a51c](https://github.com/st0o0/ran/commit/541a51c8392e6d71b7906365821bf57ad9a92ff3))
* update SECURITY.md ([1623919](https://github.com/st0o0/ran/commit/1623919330d424a3ebee48b14d69505a1ce6e049))

## [0.3.8](https://github.com/st0o0/ran/compare/v0.3.7...v0.3.8) (2026-10-23)


### Features

* decouple release-please from build workflow ([0d1d25d](https://github.com/st0o0/ran/commit/0d1d25d7e3f3b304621d301bfcfcc131277fef41))
* extend docker preset for base image digest pinning + automerge ([81946bd](https://github.com/st0o0/ran/commit/81946bdc09b84510df8ba38ef92c57e59a9047fb))
* migrate to modular build and docker workflows ([e4ecb28](https://github.com/st0o0/ran/commit/e4ecb286749674c4577c1dda838a43b9d69418ca))
* migrate to multi-stage Dockerfile ([05c800f](https://github.com/st0o0/ran/commit/05c800f3237788ac626295ed099c35ae04306d63))


### Bug Fixes

* add id-token permission for cosign signing in dev builds ([533344a](https://github.com/st0o0/ran/commit/533344a4d7ac000194e7c1d08b7961b836a20107))
* grant contents:read and drop paths filter in dev-build docker job ([e251287](https://github.com/st0o0/ran/commit/e251287d3400d75d5a1e22219568a7ae29783984))
* grant pull-requests/issues write permission to labeler and label-sync callers ([b7e76f6](https://github.com/st0o0/ran/commit/b7e76f6e82a3dd6cf4b3215ebfa89ab5a325a846))
* harden traps and alerter against spoofing and resource exhaustion ([0d82386](https://github.com/st0o0/ran/commit/0d82386da30c04c9168d56ed87fa42fd269eff69))


### Documentation

* align README badges ([0983504](https://github.com/st0o0/ran/commit/0983504e203aa68ba8f55e83d46c74e26505f29c))
* **openspec:** add security-hotfix and sensor-redesign changes, archive dynamic-ban-escalation ([0c7bb38](https://github.com/st0o0/ran/commit/0c7bb38e2c1f80aa2f16919d77df9afc0ac72e10))
* remove em dashes and simplify wording ([069091d](https://github.com/st0o0/ran/commit/069091d0505f32ec3d87d96a63ce746e23cf9f74))
* update project context and rules ([8753d04](https://github.com/st0o0/ran/commit/8753d047d53d423aacf12c4eb0fd3004f3555aa3))


### Refactoring

* migrate to shared reusable workflows ([598ef59](https://github.com/st0o0/ran/commit/598ef5982dc11755169d76019583bb9a907e2148))
* rename CI jobs for cleaner GitHub check names ([97e13dd](https://github.com/st0o0/ran/commit/97e13dd31c676ccd1726e2db78c55a442da999a0))


### Dependencies

* bump golang from 1.26.6-alpine to 1.27.0-alpine ([1003d8d](https://github.com/st0o0/ran/commit/1003d8d22d70c92a4980b1ed917890bf4f7370ed))
* bump golang from 1.27.0-alpine to 1.27.1-alpine ([7a8a5bb](https://github.com/st0o0/ran/commit/7a8a5bb5bc52fa91990e04cf9ad328ec1ef6001a))
* bump golang.org/x/crypto from 0.55.0 to 0.56.0 in the go-all group ([67d1388](https://github.com/st0o0/ran/commit/67d1388e7c87fb2877a234fc79a5ae0d8c07c175))
* bump hadolint/hadolint-action in the actions-all group ([29d3a3f](https://github.com/st0o0/ran/commit/29d3a3f8c508e9e85a3d8bfaf59062f5ef66b4c2))

## [0.3.8](https://github.com/st0o0/ran/compare/v0.3.7...v0.3.8)


### Security

* HTTP trap no longer uses client IP headers for alerts; the validated header value is logged as `claimed_client_ip` and the connection source is used instead
* UDP traps (dns, ntp, snmp, sip) no longer alert CrowdSec because UDP source addresses are spoofable
* UDP traps are rate limited per source and globally (`RAN_UDP_RATE_PER_SOURCE`, `RAN_UDP_RATE_BURST`, `RAN_UDP_RATE_GLOBAL`)
* bounded reads for redis, ldap, telnet, http and PROXY protocol parsing (argument counts, bulk and BER lengths, line lengths, body size)
* panic isolation per handler, accept loop and UDP packet, counted in `ran_panics_recovered_total`
* alerts for non-global addresses are rejected via an explicit IP denylist
* dedup map and decision cache are capped (`RAN_CROWDSEC_MAX_TRACKED`)
* passwords are no longer sent to CrowdSec; logging them is controlled by `RAN_LOG_PASSWORDS` (`off` default, `mask`, `on`)


### Changed

* **BREAKING:** with `RAN_PROXY_PROTOCOL` enabled a valid PROXY v1/v2 header is now required; connections without one are closed and counted
* dedup slots are only recorded after a successful enqueue
* PROXY headers are parsed off the accept path under a deadline with a bounded number of pending handshakes
* `RAN_UDP_RATE_BURST` below `RAN_UDP_RATE_PER_SOURCE` is rejected at startup


### Added

* metric `ran_proxy_protocol_dropped_total`
* metric `ran_udp_rate_limited_total{protocol}`
* metric `ran_panics_recovered_total`
* pipeline stages `invalid` and `closed` for alerts dropped before enqueue or after the alerter was closed

## [0.3.7](https://github.com/st0o0/ran/compare/v0.3.6...v0.3.7) (2026-08-23)


### Features

* add multi-auth retries, escalating delay, SSH tarpit, and probe outcome classification ([77780ef](https://github.com/st0o0/ran/commit/77780ef06eb7624a3693c2ec0dcfd9d9528667ad))


### Bug Fixes

* handle errcheck violations in trap test files ([a610b9b](https://github.com/st0o0/ran/commit/a610b9bce751b0d77908239a30ee26f551f68522))

## [0.3.6](https://github.com/st0o0/ran/compare/v0.3.5...v0.3.6) (2026-08-22)


### Features

* overhaul observability with structured logging, outcome tracking, and pipeline metrics ([6d439b0](https://github.com/st0o0/ran/commit/6d439b0102a58ff177d5eb06da84d39672d8aced))

## [0.3.5](https://github.com/st0o0/ran/compare/v0.3.4...v0.3.5) (2026-08-19)


### Features

* add CrowdSec alert deduplication, batching, and decision cache ([78eaac6](https://github.com/st0o0/ran/commit/78eaac6c1f966737bccd4871569d12b54852eebe))

## [0.3.4](https://github.com/st0o0/ran/compare/v0.3.3...v0.3.4) (2026-08-17)


### Features

* add multi-port listener support and ADB/Minecraft traps ([0bc1c25](https://github.com/st0o0/ran/commit/0bc1c255180c1402478b8b9849913292a21b23fe))


### Bug Fixes

* resolve data races in ADB and Minecraft test teardown ([320decf](https://github.com/st0o0/ran/commit/320decf629e98a155ed4399f4723a0118848164a))
* resolve golangci-lint errcheck and staticcheck findings ([62e4745](https://github.com/st0o0/ran/commit/62e47458aaa2cccc63c2c08b4a389cabf84aee40))

## [0.3.3](https://github.com/st0o0/ran/compare/v0.3.2...v0.3.3) (2026-08-16)


### Bug Fixes

* **crowdsec:** add missing events field and enrich alerts with trap metadata ([659d034](https://github.com/st0o0/ran/commit/659d034fe67dee0521c0a6588c6fab6b3f896bc2))

## [0.3.2](https://github.com/st0o0/ran/compare/v0.3.1...v0.3.2) (2026-08-16)


### Bug Fixes

* **crowdsec:** use custom origin instead of reserved crowdsec origin ([65e9be2](https://github.com/st0o0/ran/commit/65e9be2cc3237986689b39ed923a729917eaccc7))

## [0.3.1](https://github.com/st0o0/ran/compare/v0.3.0...v0.3.1) (2026-08-16)


### Features

* **health:** Add /healthz endpoint and improve healthcheck ([9f0681d](https://github.com/st0o0/ran/commit/9f0681d2a49e4294ad23c8f497f5b04b4a04c3b2))


### Bug Fixes

* check json.Encode error return in healthz handler ([ad575f6](https://github.com/st0o0/ran/commit/ad575f6da1734a83057900a686faa6ea286910a1))

## [0.3.0](https://github.com/st0o0/ran/compare/v0.2.0...v0.3.0) (2026-08-15)


### Features

* replace CrowdSec API-key auth with machine-login JWT ([94e9950](https://github.com/st0o0/ran/commit/94e9950d98ae8a1cd1a3415c2fbdf9baf3614375))


### Bug Fixes

* check json.Encode error returns in crowdsec tests ([f9e88f0](https://github.com/st0o0/ran/commit/f9e88f0be886de4e3cdda3492f0f16b8130b765a))

## [0.2.0](https://github.com/st0o0/ran/compare/v0.1.1...v0.2.0) (2026-08-12)


### Features

* enrich session logging with duration, counters, and human-readable messages ([0a269e2](https://github.com/st0o0/ran/commit/0a269e2d7ff643cefb061948831d4b66f1c93719))

## [0.1.1](https://github.com/st0o0/ran/compare/v0.1.0...v0.1.1) (2026-08-11)


### Bug Fixes

* track HTTP sessions per TCP connection and add PROXY protocol support ([6425938](https://github.com/st0o0/ran/commit/64259380befcc6a79f6e52f386ee6d17e76b64b8))

## 0.1.0 (2026-08-11)


### Features

* add command and payload traps for Memcached, Elasticsearch, HTTP Proxy, Modbus, DNS, SNMP, SIP, NTP ([3247ab3](https://github.com/st0o0/ran/commit/3247ab38bfca6d2cab2ec5bb85b9c9c7d62cdb36))
* add credential-capture traps for FTP, Telnet, SMTP, POP3, IMAP, Redis, IRC, PostgreSQL, MSSQL, Oracle, LDAP, SMB, SOCKS5, RDP, VNC, MQTT ([52ca86d](https://github.com/st0o0/ran/commit/52ca86d958395c015d5b646b467a471078bada9a))
* add protocol-appropriate input size limits to text traps ([2c27dac](https://github.com/st0o0/ran/commit/2c27dac532c87f569eb2d23cba3c644480324fda))
* add SSH, HTTP, and MySQL honeypot traps with CrowdSec alerting ([7b0dad8](https://github.com/st0o0/ran/commit/7b0dad86866e2519b73fb21dd1a693fe76ab4a07))


### Bug Fixes

* resolve all errcheck lint violations ([1243474](https://github.com/st0o0/ran/commit/1243474c5c6ca77f01c4d5a2b7bb2eb960623186))
* resolve all errcheck lint violations ([6b96eab](https://github.com/st0o0/ran/commit/6b96eabf753e088bab29cc93df6e3297558e3ca4))
* resolve errcheck, ineffassign, and unused lint violations ([55cc3d0](https://github.com/st0o0/ran/commit/55cc3d08f2426a4fac4db0cab33858e4f506e771))
* surface trap startup errors with log-and-continue strategy ([14ade9e](https://github.com/st0o0/ran/commit/14ade9e2256b2002c2c4f434abdb6c2fb2913075))
* use RAN_TRAPS in e2e test script ([06e5774](https://github.com/st0o0/ran/commit/06e577452570c4e013e5c1de2d5ba404eeba6211))
* use short variable declaration in metrics test ([a444bb3](https://github.com/st0o0/ran/commit/a444bb38999053fafbb3ae42bea6a7671de9dc62))


### Documentation

* add OpenSpec specs for all new traps and archive change artifacts ([0c312e5](https://github.com/st0o0/ran/commit/0c312e5fb529f762bddbc1c7a37d6a5ed4d2a66d))
