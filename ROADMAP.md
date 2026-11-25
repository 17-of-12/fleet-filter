# Roadmap

Work that is planned and not built. Everything else in this repository describes what the code does
today; a capability that appears here does not exist yet, and should not be relied on.

Order is rough intent, not a schedule.

## Detection

| item | why | state |
|---|---|---|
| Novelty detection | A signature only matches what someone already described. Clustering request shapes and scoring the unfamiliar is how an undescribed attack gets noticed. | designed, not built |
| Response-body inspection | All detection today is request-side. An attack whose only observable is in the response is invisible. | not started |
| Shape counters for nested or oversized structures | Literal body markers cannot see a small body that is expensive to parse (deep nesting, many fields). | not started |

## Deception fidelity

| item | why | state |
|---|---|---|
| Generate gateway and responder bodies from one catalogue | The gateway serves a short static body; the responder serves the full profile page. A client can tell them apart by content, which contradicts presenting one fake application. | not started |
| Machine-readable responder contract | `docs/spec/responder-interface.md` is prose, so a third implementation is reviewed against prose. A recorded request/response fixture set would make it testable. | not started |

## Transport

| item | why | state |
|---|---|---|
| Backend TLS | The upstream leg is plaintext HTTP/1.1 only; a backend that requires TLS cannot be used. | not started |
| WebSocket upgrade | `connection` and `upgrade` are stripped as hop-by-hop, so an upgraded connection is refused rather than proxied. | not started |
| HTTP/3 | Not supported. | not started |

## Operations

| item | why | state |
|---|---|---|
| Automated PoC acquisition | Fetching exploit code into the tree is a supply-chain decision; until it is made, the fetch is a recorded manual act. | not started |
| On-demand lab victims | The lab manifest declares intent and `bin/lab-inventory.py` reports reality; reconciling the two automatically would hide drift. | not started |
| Scheduled corpus replay | Replay is manual today because the corpus is small. | not started |
| Cross-host attacker state | Quarantine is per host. Sharing attacker observations between hosts is a policy and privacy decision as much as a technical one. | not started |

## What is not on this roadmap

- Becoming a general-purpose WAF, or a replacement for patching.
- Attacking or retaliating against scanners.
- Detecting every unknown exploit. The item above is an attempt at noticing the unfamiliar, not a
  promise of coverage.
