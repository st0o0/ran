---
layout: home

hero:
  name: rán
  text: Honeypot sensor for CrowdSec
  tagline: Single-binary honeypot written in Go. Emulates 40 network services, captures credentials and payloads as structured JSON and pushes classified alerts to CrowdSec, whose profiles decide the bans.
  actions:
    - theme: brand
      text: Getting started
      link: /getting-started
    - theme: alt
      text: Traps
      link: /traps

features:
  - title: 40 traps
    details: SSH, RDP, Modbus, MQTT and more. Each trap handles the handshake, captures what matters and returns a plausible error.
  - title: Classified alerts
    details: Every TCP session is classified as probe, attack or scan, so CrowdSec profiles can escalate bans per class and per repeat offender.
  - title: Hardened by design
    details: The alert identity is always the socket peer, UDP traps never alert, every read is bounded and passwords never leave the host.
  - title: Small and easy to run
    details: One static binary, environment-variable configuration, a health endpoint and built-in Prometheus metrics.
---
