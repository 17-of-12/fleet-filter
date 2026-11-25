# Responder interface — what the gateway may call, and what stays outside it

This is the normative interface. It applies to `tarpit/server/server.py` (the reference
implementation), to the inline responder in `gateway/src/deception.rs`, and to any future responder
— a Rust rewrite or a container — that wants to sit behind the
gateway.

## Why an interface at all

The owner's hybrid decision was: lightweight deception may live inside the gateway, but the full
deception engine must stay outside the process that protects legitimate traffic, because a stateful
responder that leaks memory or blocks a task takes the front end down with it. Saying "pluggable"
is not enough — the only thing that makes a responder swappable is a written contract that both the
current and the future implementation satisfy. That contract is this file.

Two failure modes it exists to prevent:

1. **Fingerprint drift.** If the gateway answers a quarantined client with `server:
   fleet-filter-gateway/0.1.0` and the responder answers the same client with `server:
   Apache/2.4.37`, the client learns that it was classified. Every implementation must present the
   same observable surface for the same request class.
2. **Accidental forking.** Without a named interface, the next implementation is written by reading
   the Python code, and the Python code becomes the spec — including its bugs. The contract is
   written here so an implementation can be reviewed against it instead of against another file.

## The contract

A responder answers one request with one response. These are the fields a client can observe, and
what each implementation must do with them.

| Field | Contract |
|---|---|
| Status | Must match the profile chosen for the request class. `generic` → 403, `exploit-probe` → 404, `api-probe` → 200. A responder never answers 200 for a path it would not really serve. |
| `Server` | The identity the client would see from the real backend for that request class. The inline responder sends `fleet-filter-gateway/<version>`; the Python responder sends the configured banner. This is the one field where the two implementations differ today, and it is a known gap (see Gaps). |
| `Content-Type` | From the profile. `text/html; charset=UTF-8` for HTML profiles, `application/json` for API profiles. |
| Body | From a **reviewed profile**, never from a live docroot. The Python responder reads `/opt/tarpit/responses/*.html` via `index.json` (PT-03: reading the docroot leaked raw PHP source and followed a symlink to `/etc/passwd`); the inline responder uses compile-time static bodies, which cannot leak at all. |
| `X-Tarpit` | Opt-in marker (`--advertise` on the responder, PT-12). Present only when the operator asked for it; its absence must not change the response. |
| `X-Tarpit-Client` | The client IP the responder believes made the request, trusted only from `--trusted-proxy` peers (PT-10). The gateway sets it for proxied requests; a responder that ignores it will log the proxy address instead of the client. |
| `X-Tarpit-Signature` | The signature name that matched, forwarded by the gateway (`SetEnvIf`-derived on Apache, `x-fleet-filter-*` on the gateway). A responder that receives it must not re-derive the signature from the path alone. |
| `X-Fleet-Filter-Class` | The classification and its source (`tarpitted;source=map`, `...;source=memo`, `...;source=fallback`). Present whenever the gateway classified the client, so a captured response says how the gateway knew. |
| `X-Fleet-Filter-Posture` | The policy rule that produced a local rejection (`method_not_allowed`, `paused`, …). |
| `X-Fleet-Filter-Deception` | The inline profile, the planned first-byte-to-last-byte duration and the piece count (`exploit-probe;drip_ms=2300;chunks=47`), so the shape is documented by the response itself. On budget exhaustion the value is `budget-exhausted` and there is no drip. Changed 2026-11-24 from `delay_ms=N`: the old field named a pause the gateway no longer takes. |
| Delay | Either a drip schedule (Python responder: fixed-size chunks over N seconds) or a single bounded delay (inline: `min(profile.delay_ms, max_drip_ms)`). Either way the response must complete; a responder that stalls a connection past its ceiling is a bug, not a feature. |
| Connection handling | Response `Content-Length` must match the bytes sent (a mismatch is `curl` error 18, seen in testing). Request bodies must be drained or the connection closed (PT-06: an unread POST body made the next pipelined request parse as `ABCDGET`). Keep-alive must be preserved for normal responses. |
| Concurrency | Every implementation bounds itself: the responder with global and per-IP semaphores plus a socket timeout (PT-07); the inline path with `DripBudget` (`max_concurrent_drips`, RAII permits). A responder with no bound is the reason the engine stays outside the gateway. |

## How a backend is chosen

`[routing] default_backend` is the only routing knob today, and it is a URL, not a code path — the
deployment-profile contract says the gateway's decision must never depend on the backend type, so
native Apache, a container, or a remote host are all the same kind of value. That is what makes the
migration path a policy edit:

| Desired shape | Bundle change | Code change |
|---|---|---|
| Answer everything from the backend (pre-R behaviour) | `on_quarantined = "proxy"`, no `[deception]` | none |
| Answer quarantined clients inline, everything else from the backend | `on_quarantined = "inline"` + `[deception]` | none |
| Answer quarantined clients with a cheap 503 | `on_quarantined = "reject"` | none |
| Point the gateway at a containerised responder instead of Apache | `default_backend = "http://127.0.0.1:<port>"` | none |

## The claim side of the interface

A responder that *recognises* something also reports it. Both producers write the same claim record
(`SCHEMA_VERSION = 1` in `controller/adaptive-tarpit.py`) into **their own** spool directory, and
the controller drains each one on its timer:

| Producer | Spool | Ownership |
|---|---|---|
| Python responder | `/var/lib/adaptive-tarpit/spool` | `nobody:nobody 0755` |
| Gateway | `/var/lib/fleet-filter-gateway/spool` | `fleet-filter-gw:fleet-filter-gw 0750` |
| Future container responder | its own directory, owned by its own account | required, not optional |

One directory per producer is the rule (R1): a shared directory would let one producer's bad file
block another's, and ownership is how R6's permission boundary survives — nobody writes to another
producer's spool, and nothing but the controller writes SQLite.

## What the gateway guarantees that a responder cannot

* **Reload safety.** A policy reload swaps one `Arc`; a connection in flight is served entirely by
  the configuration it was accepted with. A responder behind the gateway inherits this and does not
  need its own reload mechanism to be safe.
* **Cost ceiling.** The gateway's inline path allocates exactly the profile body and holds a slot
  for at most `max_drip_ms`. A stateful responder's cost is its own problem, which is the point of
  keeping it outside.

## Known divergences

| divergence | current state | tracked as |
|---|---|---|
| `Server` banner | met: `[deception] server_banner` sets it, so the inline responder presents whatever the operator configures | - |
| response body | gateway serves a short compile-time body; the responder serves the full profile page | roadmap: generate both from `tarpit/profiles/catalogue.yaml` |
| HTTP contract | this document is prose; no machine-readable fixture set exists | roadmap: record fixtures |
| drip shape | met: `deception::DripBody` streams in `chunk_size` pieces with `chunk_delay_ms` gaps and declares `Content-Length` | - |
