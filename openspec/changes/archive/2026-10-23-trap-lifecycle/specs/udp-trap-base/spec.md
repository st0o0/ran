## ADDED Requirements

### Requirement: UDP Stop honours its context
`Stop(ctx)` on a UDP trap SHALL close all sockets and wait for in-flight packet handlers, and SHALL return `ctx.Err()` when the context ends before they finish.

#### Scenario: Handler stuck at shutdown
- **WHEN** a packet handler does not return before the `Stop` context deadline
- **THEN** `Stop` returns the context error at the deadline
