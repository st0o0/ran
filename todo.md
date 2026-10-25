# todo

Roadmap for `ran`, derived from a comparison with Cowrie, OpenCanary, qeeqbox/honeypots, T-Pot (and its components) and Beelzebub/Galah, plus an audit of the traps in this repo (2026-10-24). Order is the planned order of work. Keep this file short and factual; update it whenever a change is created, archived or dropped.

Rules: each item is one OpenSpec change (`openspec/changes/<name>`) unless marked `docs`. All 13 changes below are written and validated; the order is the order of implementation. *Now* is what to build first. Delete an item (or link the archived change) when it ships. Effort: S = a few hundred lines, M = a protocol with state, L = a subsystem. Everything must keep the checklist in `AGENTS.md` (bounded reads, no trust in client identity, UDP never alerts, passwords never to CrowdSec).

## Now (build next)

| # | Change | Content | Effort | Source |
|---|---|---|---|---|
| 12 | `ics-and-printer-traps` | S7comm 102, EtherNet/IP 44818, JetDirect/PJL 9100, IPP 631 (TCP only; BACnet and IPMI are UDP and would log only) | M | T-Pot (Conpot), qeeqbox |
| 13 | `webhook-sink` | One generic webhook, rate limited, no passwords. **Deferred by decision**: the change is written, do not implement it yet | S | OpenCanary, Beelzebub |

## Docs site (evaluate after `fingerprint-realism` and `ics-and-printer-traps`)

The README is about 1000 lines and used as reference documentation. Evaluate a VitePress site: what it would cost (Node toolchain in CI, GitHub Pages deploy workflow, a pinned VitePress version managed by renovate), what it buys (sidebar and search, one page per topic, versioned config and metric reference), and what stays in the README (pitch, comparison, quick start, trap list, link to the site). Open questions:

- `docs/` is gitignored ("local only design docs"); either rename the site folder (for example `site/`) or change the ignore rule and move the local design docs.
- Several README facts are checked by contract tests (`RAN_*` variables, trap names); decide whether the tests keep reading the README or read the new pages, so the guarantee does not silently lapse.
- Generate what can be generated instead of copying: the trap table and config reference from `config.DefaultPorts` and the contract test lists, so the site cannot drift.
- Competitor facts (Cowrie licence, OpenCanary protocol list, T-Pot container count) need re-checking before they move into the site.

Outcome of the evaluation is a go or no-go with a rough size, then an OpenSpec change (`docs-site`) if go.

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
