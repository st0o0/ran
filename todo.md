# todo

Roadmap for `ran`, derived from a comparison with Cowrie, OpenCanary, qeeqbox/honeypots, T-Pot (and its components) and Beelzebub/Galah, plus an audit of the traps in this repo (2026-10-24). Order is the planned order of work. Keep this file short and factual; update it whenever a change is created, archived or dropped.

Rules: each item is one OpenSpec change (`openspec/changes/<name>`) unless marked `docs`. All 13 changes below are written and validated; the order is the order of implementation. *Now* is what to build first. Delete an item (or link the archived change) when it ships. Effort: S = a few hundred lines, M = a protocol with state, L = a subsystem. Everything must keep the checklist in `AGENTS.md` (bounded reads, no trust in client identity, UDP never alerts, passwords never to CrowdSec).

## Now (build first)

| # | Change | Why | Effort | Source |
|---|---|---|---|---|
| 1 | `http-request-capture` | `GET` scanners are invisible: no path, no user agent, class stays `probe`, never reported | M | audit, T-Pot (Log4Pot) |
| 2 | `tls-traps` | No TLS anywhere; SNI, JA3 and JA4 lost; most scans hit 443 | M | qeeqbox, T-Pot, audit |
| 3 | `ssh-identity-capture` | Key-only bots rejected silently; no client version or HASSH | S-M | Cowrie, audit |
| 4 | `ignore-list` | Own scanners and monitors get classified and banned | S | OpenCanary |

Docs: the README comparison, positioning section and collapsible reference sections are done. Re-check the competitor facts (Cowrie licence, OpenCanary protocol list, T-Pot container count) against the repos before the next README update.

## Next

| # | Change | Content | Effort | Source |
|---|---|---|---|---|
| 5 | `new-scan-targets` | Traps for Docker API 2375, Kubernetes 6443 and 10250, MongoDB 27017; `telnet` default also on 2323. One task per trap (registry, ports and README must change together) | S-M each | audit, T-Pot |
| 6 | `classification-depth` | Modbus read versus write, ADB continue after AUTH, telnet IAC handling, more than one attempt for mysql, postgres and rdp, scan detection by distinct ports | S-M | audit |

## Later

| # | Change | Content | Effort | Source |
|---|---|---|---|---|
| 10 | `proxy-protocol-allowlist` | Source CIDR allowlist for who may send PROXY headers (already in AGENTS.md follow-ups) | S | internal |
| 11 | `fingerprint-realism` | Vary SSH banner, MySQL and Elasticsearch versions; per-trap class meta for vnc and single-request traps | S | audit |
| 12 | `ics-and-printer-traps` | S7comm 102, EtherNet/IP 44818, JetDirect/PJL 9100, IPP 631 (TCP only; BACnet and IPMI are UDP and would log only) | M | T-Pot (Conpot), qeeqbox |
| 13 | `webhook-sink` | One generic webhook, rate limited, no passwords. **Deferred by decision**: the change is written, do not implement it yet | S | OpenCanary, Beelzebub |

## To discuss next (all other changes are written)

`crowdsec-integration`: how rán relates to CrowdSec beyond the alert push. Candidate points:

- Ship the example profiles and a rán log parser as a Hub collection (the Hub has only a Cowrie text parser and open community PRs).
- Sync the ignore list from LAPI allowlists.
- Ask the LAPI whether a source is already banned and skip the alert.
- Optional second sink (AbuseIPDB) for operators without CrowdSec.
- Documented CAPI sharing choices per class.

## Icebox: needs an explicit design decision first

These conflict with the current "sensor, no shell, bounded reads" model in `AGENTS.md`. Decide first in a design change ("interaction tier": an off-by-default, isolated mode with its own limits). Only then plan the single items.

- Post-auth SSH and telnet session: fake shell and filesystem, `exec` capture, `direct-tcpip` logging (log only, never dial).
- Capturing download URLs from commands (log only, never fetch) and uploaded files.
- Session replay.
- LLM-generated responses (cost, prompt injection, data leaving the host).

## Rejected, with reason

| Idea | Reason |
|---|---|
| Portscan detection via iptables logs (OpenCanary) | Needs root and host firewall access; breaks the single binary model |
| Samba file-share canary (OpenCanary) | Needs a real Samba, large attack surface |
| Packet sniffer (qeeqbox), Suricata, p0f | Needs raw sockets or libpcap |
| Database sinks, RabbitMQ, e-mail and Teams alerts | JSON logs, metrics and CrowdSec already cover them |
| UDP-only traps with no alert value (DHCP, TFTP, SSDP, chargen) | UDP never alerts; reflection risk |
| Go plugins in process (Beelzebub) | Runs foreign code inside the sensor |
| Copying code from Beelzebub | GPL-3.0; ideas only, clean-room |

## Sources

Cowrie, OpenCanary, qeeqbox/honeypots, T-Pot and Beelzebub repositories and the CrowdSec Hub, read 2026-10-24 (some via page summaries; numbers such as T-Pot container counts are unverified). Idle memory of the current build was measured at 13 MB working set with all 29 traps enabled (Windows).
