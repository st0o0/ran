---
aside: false
---

# Config builder

Pick a deployment scenario, enable traps, adjust settings and copy the result as an
env file, a `docker-compose.yml` or a `docker run` line. Only values that differ
from the default are written.

Everything runs in your browser. The page sends nothing anywhere and stores
nothing; the share link keeps the configuration in the URL hash only. The CrowdSec
password is never asked for: the output contains `CHANGE_ME`, replace it at
deployment time. The rules shown under *Check* mirror the startup validation, and
`ran check-config` remains the authority. For background see
[Configuration](/configuration), [Traps](/traps) and
[Hardening](/hardening#behind-a-reverse-proxy).

<ClientOnly>
  <ConfigBuilder />
</ClientOnly>
