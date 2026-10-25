# Comparison with alternatives

::: warning
Facts last checked October 2026 (2026-10-24), verify before relying. The figures come from the projects' own READMEs at that time and may be out of date.
:::

There are good honeypots out there, and they answer different questions. rán is
built for one job: be a cheap, hardened **sensor** whose alerts a CrowdSec
profile can act on.

| | Cowrie | OpenCanary | qeeqbox/honeypots | T-Pot | Beelzebub | rán |
|---|---|---|---|---|---|---|
| Language / runtime | Python 3.11+ | Python 3.10+ | Python (pip) | Docker Compose stack | Go | Go, static binary |
| Focus | Interactive SSH/Telnet shell | Tripwire for internal networks | Many protocol servers | Platform of many honeypots | Deception framework, optional LLM | Sensor for blocklists |
| Protocols | SSH, Telnet (SFTP/SCP) | multi-protocol, list not verified | 29 modules | 31 honeypots listed | SSH, HTTP, TCP, Telnet, MCP | 40 stubs |
| Post-login shell, file capture | yes | no | no | via Cowrie, Dionaea | optional LLM shell | no (by design) |
| CrowdSec | log parsing via the Hub | none found | none found | none found | none found | native LAPI alerts, classified |
| Footprint | Python process | Python process | Python process | 8 GB (sensor) to 16 GB (hive) RAM | Go binary | about 15 MB working set idle, all 40 traps |
| Prometheus metrics | no | no | no | via the stack | optional | built in |
| Licence | see repo | BSD-3 | AGPL-3.0 | GPL-3.0 | GPL-3.0 | MIT |

Read from the projects' own READMEs in October 2026; check them for current
details. "None found" means the README does not mention it. The memory figure
for rán was measured on Windows with a freshly built binary, all 40 traps enabled and listening (checked in `/healthz`) and no traffic (working set after 30 seconds idle: median of five samples, 15.0 MB; measured on Windows, 40 traps, one run).

What rán does better:

- **Alert quality.** Every TCP session is classified as `probe`, `attack` or
  `scan`, repeated alerts per source are limited by a cooldown, and alerts carry
  no decisions, so CrowdSec profiles can escalate bans per class and per repeat
  offender.
- **Hardened by design.** The alert identity is always the socket peer, UDP traps
  never alert (spoofable), every read is bounded, passwords never leave the host,
  and the parsers are fuzzed.
- **Small and easy to run.** One static binary, environment-variable config,
  `check-config`, a health endpoint and Prometheus metrics.

What rán deliberately does not do, and where to look instead:

- **No interactive session.** There is no shell, no filesystem emulation, no file
  download or upload capture and no LLM. To study what attackers type after they
  log in, use Cowrie, Beelzebub or T-Pot.
- **Stubs, not servers.** Most traps handle one handshake and return a plausible
  error. Depth varies by protocol (see [Traps](/traps)).
- **Not stealthy.** Banners are generic; a determined attacker can fingerprint any
  honeypot (see [Threat model](/hardening#threat-model)).

Use rán to turn internet-facing probes into CrowdSec bans on a small host. Choose
or add another honeypot when you want attacker behavior, malware samples or an
internal tripwire.
