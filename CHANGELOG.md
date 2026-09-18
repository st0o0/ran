# Changelog

## [0.3.8](https://github.com/st0o0/ran/compare/v0.3.7...v0.3.8) (2026-09-18)


### Features

* decouple release-please from build workflow ([0d1d25d](https://github.com/st0o0/ran/commit/0d1d25d7e3f3b304621d301bfcfcc131277fef41))
* extend docker preset for base image digest pinning + automerge ([81946bd](https://github.com/st0o0/ran/commit/81946bdc09b84510df8ba38ef92c57e59a9047fb))
* migrate to modular build and docker workflows ([e4ecb28](https://github.com/st0o0/ran/commit/e4ecb286749674c4577c1dda838a43b9d69418ca))
* migrate to multi-stage Dockerfile ([05c800f](https://github.com/st0o0/ran/commit/05c800f3237788ac626295ed099c35ae04306d63))


### Bug Fixes

* add id-token permission for cosign signing in dev builds ([533344a](https://github.com/st0o0/ran/commit/533344a4d7ac000194e7c1d08b7961b836a20107))
* grant contents:read and drop paths filter in dev-build docker job ([e251287](https://github.com/st0o0/ran/commit/e251287d3400d75d5a1e22219568a7ae29783984))


### Documentation

* align README badges ([0983504](https://github.com/st0o0/ran/commit/0983504e203aa68ba8f55e83d46c74e26505f29c))
* update project context and rules ([8753d04](https://github.com/st0o0/ran/commit/8753d047d53d423aacf12c4eb0fd3004f3555aa3))


### Refactoring

* migrate to shared reusable workflows ([598ef59](https://github.com/st0o0/ran/commit/598ef5982dc11755169d76019583bb9a907e2148))
* rename CI jobs for cleaner GitHub check names ([97e13dd](https://github.com/st0o0/ran/commit/97e13dd31c676ccd1726e2db78c55a442da999a0))


### Dependencies

* bump golang from 1.26.6-alpine to 1.27.0-alpine ([1003d8d](https://github.com/st0o0/ran/commit/1003d8d22d70c92a4980b1ed917890bf4f7370ed))
* bump golang from 1.27.0-alpine to 1.27.1-alpine ([7a8a5bb](https://github.com/st0o0/ran/commit/7a8a5bb5bc52fa91990e04cf9ad328ec1ef6001a))
* bump golang.org/x/crypto from 0.55.0 to 0.56.0 in the go-all group ([67d1388](https://github.com/st0o0/ran/commit/67d1388e7c87fb2877a234fc79a5ae0d8c07c175))
* bump hadolint/hadolint-action in the actions-all group ([29d3a3f](https://github.com/st0o0/ran/commit/29d3a3f8c508e9e85a3d8bfaf59062f5ef66b4c2))

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
