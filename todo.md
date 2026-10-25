# todo

Roadmap for `ran`, derived from a comparison with Cowrie, OpenCanary, qeeqbox/honeypots, T-Pot (and its components) and Beelzebub/Galah, plus an audit of the traps in this repo (2026-10-24). Order is the planned order of work. Keep this file short and factual; update it whenever a change is created, archived or dropped.

Rules: each item is one OpenSpec change (`openspec/changes/<name>`) unless marked `docs`. All 15 changes below are written and validated; the order is the order of implementation. *Now* is what to build first. Delete an item (or link the archived change) when it ships. Effort: S = a few hundred lines, M = a protocol with state, L = a subsystem. Everything must keep the checklist in `AGENTS.md` (bounded reads, no trust in client identity, UDP never alerts, passwords never to CrowdSec).

## Now (build next)

| # | Change | Content | Effort | Source |
|---|---|---|---|---|
| 14 | `docs-site` | VitePress site in `docs/` (layout of FunkArr and njord, shared `docs.yml` deploy, pnpm renovate preset), generated trap table, contract tests read README plus site; README shrinks in stage 2 | M | evaluation 2026-10-25 |
| 15 | `crowdsec-integration` | Shipped example profile (`ran_scan`, `ran_attack`, `ran_noban`) printed by `ran crowdsec-profile`, plus a CI test against a pinned real CrowdSec LAPI (escalation, probe, allowlist) | M | operator setup 2026-10-25 |
| 13 | `webhook-sink` | One generic webhook, rate limited, no passwords. **Deferred by decision**: the change is written, do not implement it yet | S | OpenCanary, Beelzebub |

## Docs site (evaluate after `fingerprint-realism` and `ics-and-printer-traps`)

The README is about 1000 lines and used as reference documentation. Evaluate a VitePress site: what it would cost (Node toolchain in CI, GitHub Pages deploy workflow, a pinned VitePress version managed by renovate), what it buys (sidebar and search, one page per topic, versioned config and metric reference), and what stays in the README (pitch, comparison, quick start, trap list, link to the site). Open questions:

- `docs/` is gitignored ("local only design docs"); either rename the site folder (for example `site/`) or change the ignore rule and move the local design docs.
- Several README facts are checked by contract tests (`RAN_*` variables, trap names); decide whether the tests keep reading the README or read the new pages, so the guarantee does not silently lapse.
- Generate what can be generated instead of copying: the trap table and config reference from `config.DefaultPorts` and the contract test lists, so the site cannot drift.
- Competitor facts (Cowrie licence, OpenCanary protocol list, T-Pot container count) need re-checking before they move into the site.

Status: stage 1 shipped locally (site, generator, CI); stage 2 (shrink the README) waits for GitHub Pages. Evaluation result (2026-10-25): go, medium size, no sensor risk. Proposed cut for the `docs-site` change: a `site/` folder with a pinned VitePress and its own `package.json`; contract tests read the README and every page under `site/`; generate only the trap table from `config.DefaultPorts` and guard it with `git diff --exit-code` in CI; a GitHub Pages workflow (repository setting needed from the owner); migrate in stages (configuration, metrics, CrowdSec and upgrade notes first, then shrink the README). The renovate `pnpm` preset covers npm (checked). Decision 2026-10-25: use `docs/` like FunkArr and njord (no local design docs exist, the ignore rule is replaced); the change is written as `docs-site` (item 14).

## CrowdSec integration (written as `crowdsec-integration`, steps 1 and 2; steps 3 and 4 stay open)

`crowdsec-integration`: how rán relates to CrowdSec beyond the alert push. Proposed order:

1. CI integration test with a real CrowdSec container, the shipped profile and rán: an alert must lead to a decision with escalation. Today "verified against v1.8.1" is a manual README statement.
2. Ship the example profile as a file in the repo and print it with a subcommand, so it matches the binary version.
3. Spike: can LAPI allowlists be queried to feed the ignore list? Probably needs a separate bouncer key; unverified.
4. Later, optional: second sink (AbuseIPDB) for operators without CrowdSec, documented CAPI sharing choices per class.

Corrections to earlier ideas:

- A Hub collection for profiles does not work: profiles are local (`/etc/crowdsec/profiles.yaml` or `profiles.yaml.local`) and the Hub carries parsers, scenarios, postoverflows, contexts and AppSec rules. A rán log parser is of little use because rán pushes alerts through the LAPI.
- Do NOT skip alerts for sources the LAPI already bans: the 1h cooldown deliberately renews bans, and `GetDecisionsCount` counts alerts, so skipping them lowers the escalation level and lets bans lapse.

Open follow-ups: a MySQL scramble that ends in a zero byte (1 in 256) is mistaken for a clear password in seeded mode (see `openspec/changes/archive/2026-10-25-fingerprint-realism/design.md`).

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
