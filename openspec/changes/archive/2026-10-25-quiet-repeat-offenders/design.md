## Offender table

The cooldown filter forgets an entry after its window, so a repeat counter cannot live there. A second bounded table keyed by source IP holds, per class, the number of alerts sent, the time of the last alert and the shun deadline. Entries expire after `RAN_REPEAT_RESET` of silence (internal default 7 days) and the table is bounded by the same tracked-entries limit family as the existing trackers, with FIFO eviction of the oldest entry. Eviction trades memory for a missed shun, never for a wrong ban: ran stays a sensor.

## Where the check runs

- TCP skeleton: after accept and PROXY handling (so the key is the resolved source address), before `limiter.Acquire` and before the goroutine is spawned. A shunned connection is closed, counted and added to the entry's suppressed counter. No session object, so no connect/disconnect log lines.
- HTTP traps: in `ConnContext`/`ConnState` equivalent at accept time via the same helper.
- The helper lives in `Sensor` (`Shunned(ip) bool`), so the ignore check applies in one place, as AGENTS.md requires.

## Relationship to cooldown and CrowdSec

The shun window of an alert equals the cooldown that was applied to it. When the window ends, the cooldown has also ended, so the next attack alerts again. For the first `RAN_REPEAT_AFTER` alerts the window is `RAN_ALERT_COOLDOWN` (1h by default), which matches the first step of the documented ladder; afterwards it is `RAN_REPEAT_COOLDOWN`. Because the longest ban (168h) exceeds any sensible repeat cooldown, the ban never lapses between alerts.

Classes: only alerts that were actually sent (class in `RAN_BAN_ON`, passed the validity and ignore checks, accepted by the cooldown) start a shun. A suppressed lower class does not shun.

## Summary log

One `shun summary` line per source and window, emitted when the window ends lazily (on the next lookup, or by a periodic sweep of the table with a bounded batch) or when the entry is evicted. Fields: source IP, suppressed count, protocol names (at most 8, from the fixed set), window seconds. At shutdown the sweep flushes remaining summaries within the shutdown budget.

## Risks

- Lost samples: during a window only the connection that caused the alert is observed. Opt-in, and the first capture is kept. Operators who collect research data leave `RAN_SHUN` off.
- A forged PROXY header can make ran shun an arbitrary address when `RAN_PROXY_TRUSTED=any`. That setting is already documented as unsafe; the shun key uses the resolved address like everything else.
- Memory: bounded table, one small struct per source. Soak test with millions of unique sources checks the bound.
- Behavior change visible to attackers: connections close right after the first attack. That resembles a firewalled host and is the intended effect.
