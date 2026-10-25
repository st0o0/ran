# Troubleshooting

**`at least one trap must be enabled`**: set `RAN_TRAPS` to a comma-separated
list of traps. `ran check-config` validates the whole configuration.

**Port below 1024 refused**: Docker allows low ports for the unprivileged user, other
runtimes may not. Keep the defaults (`2222`, `8081`) in the container and map the
host port instead (`"22:2222"`), or see [Hardening](/hardening#recommended-container-settings).

**Port already in use**: another service is on the default port. The failing
trap logs `trap failed to start` and is skipped while the others keep running;
`ran` exits with code 1 only if all traps fail or the metrics address cannot be
bound. Override the port with `RAN_<PROTO>_ADDR=:<port>` (or `RAN_METRICS_ADDR`).

**Container exits at startup with `crowdsec login`**: with `RAN_CROWDSEC=on` the
first LAPI login happens before any trap starts, and a failure is fatal (exit code
1). The log shows one line such as
`level=ERROR msg=fatal error="crowdsec login: login request: ... no such host"` (the
hostname does not resolve) or `... login failed (status 401)` (unknown machine or
wrong password). Check that the LAPI is up and on the same Docker network as the
container, that the hostname in `RAN_CROWDSEC_URL` resolves from inside it (the
builder presets `http://crowdsec:8080`, so a container or service named
`crowdsec` must exist or you change the URL), that the machine exists
(`cscli machines list`) and that `RAN_CROWDSEC_PASSWORD` is not still `CHANGE_ME`.
`restart: unless-stopped` then restarts the container in a loop until this is fixed.

**CrowdSec alerts not arriving**: verify `RAN_CROWDSEC_URL` is reachable
from the container (without a trailing slash; it is trimmed anyway) and the
machine is registered (`cscli machines list`). With `RAN_CROWDSEC=on` a failed
first LAPI login is fatal (exit code 1); later outages are retried as described
under [CrowdSec](/crowdsec). Check `ran_crowdsec_push_errors_total` and
`ran_crowdsec_pipeline_total{stage="failed"}`.

**Alerts arrive but nothing is banned**: rán does not create decisions. Add a
CrowdSec profile for the `attack` and `scan` classes (see
[Escalation with CrowdSec profiles](/crowdsec#escalation-with-crowdsec-profiles)).

**UDP traps not receiving packets**: Docker needs explicit UDP port mapping:
`-p 53:53/udp`, not just `-p 53:53`.

**High connection volume causing drops**: increase `RAN_MAX_SESSIONS` and
`RAN_MAX_PER_IP`, or enable only the traps you need.

