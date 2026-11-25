# Responder interface — what the gateway may call, and what stays outside it

Status: **normative for Stage 2**. Applies to `tarpit/server/server.py` (the reference
implementation, deployed on lab-web01), to the inline responder in `gateway/src/deception.rs`
(T1), and to any future responder — a Rust rewrite or a container — that wants to sit behind the
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

## Gaps in this interface (recorded, not smoothed over)

1. **`Server` differs between implementations.** The inline responder says
   `fleet-filter-gateway/0.1.0`; the Python responder can be configured to match the real backend.
   For the deception to hold, the inline path needs a configurable banner. Not fixed here because it
   changes what a client sees on a live host, and that deserves its own measurement.
2. **No machine-readable schema for the HTTP contract.** This file is prose. A container image or a
   Rust rewrite would be reviewed against prose; if a third implementation appears, the contract
   should become a fixture (a recorded request/response set) before that happens.
3. **The reference responder had no `/health`** - **fixed 2026-11-14**. `GET /health`
   now answers `200` with a JSON document in ~1 ms on lab-web01 while the same process still serves
   `/ai.html` in 5.04 s, and the probe files no claim. The body carries the responder's own
   fingerprint (banner, chunk size/delay, drip cap, whether reporting is enabled), so a mis-deployed
   responder is visible from its health answer rather than only from a unit diff.
4. **Response profiles are not per-signature yet** - **fixed 2026-11-16, and the
   original wording was wrong about the mechanism.** The responder never selected "by status code
   from `index.json`": `tarpit/server/server.py` reads `X-Tarpit-Signature`, looks the value up in
   `signature_responses`, and passes the result to `profiles.select()` as `signature_profile`,
   which ranks first above the path prefix and the default. What was actually missing was the data
   on the host: `/opt/tarpit/signatures.yaml` on lab-web01 still contained only `CVE-2026-119618`,
   so the WP2Shell variants added to `controller/signatures/signatures.yaml` had no pairing on the
   box and every WP2Shell request fell through to the default profile. The store is now deployed
   from the repo (backup `/root/signatures.yaml.pre-wp2shell-*`) and the pairing table was measured
   end to end on lab-web01:

   | `X-Tarpit-Signature` | store pairing | measured |
   |---|---|---|
   | *(absent)* | no pairing, resolves by path/default to A | `200`, 1558 B |
   | `CVE-2026-119618/probe_path` | D `slow_404_app_shaped`, absent | `404`, 199 B |
   | `CVE-2026-119618/h2c_preface_on_http1_only` | D via `slow_400` alias | `400`, 199 B |
   | `CVE-2026-119618/bodyless_ct` | A `generic_slow`, vulnerable | `200`, 1558 B |
   | `CVE-2026-63030/batch_route_pretty` | D `slow_404_app_shaped` | `404`, 199 B |
   | `CVE-2026-63030/batch_route_query` | D `slow_404_app_shaped` | `404`, 199 B |
   | `CVE-2026-60137/author_not_in_injected` | D `slow_404_app_shaped` | `404`, 199 B |
   | `CVE-2026-63030` (bare CVE) | signature default | `404`, 199 B |
   | `unknown-sig` | none, falls through to A | `200`, 1558 B |

   Two contract details this surfaced, neither previously written down:

   * **The header's key format is `CVE/<variant>`, not `CVE:<variant>`.** `profiles.load_signature_responses`
     keys each variant three ways - `CVE-2026-119618/0`, `CVE-2026-119618/probe_path`, and the bare
     `probe_path` - plus `CVE-2026-119618` for the signature default. A caller that sends the
     colon form the gateway's spool uses for `claim_key` (`CVE-2026-119618:probe_path`) matches
     nothing and silently gets the default profile. Gap 2 (no machine-readable contract) is why
     this was only discoverable by reading the loader.
   * **The responder's pairings come from the signature store, not from `tarpit/profiles/catalogue.yaml`.**
     The catalogue names and aliases the profiles; `server.py` builds `signature_responses` from
     `--signature-store`. An earlier attempt to also render a `signature_responses:` block into the
     catalogue was reverted: nothing reads it, and a second copy of a mapping that the code derives
     elsewhere is the drift this project has already been bitten by three times.


## Measured divergence, 2026-11-24

Two halves of this contract were not met, and both were found by reading the code rather than by a
test:

| Half | Before | After |
|---|---|---|
| **Shape** | The gateway `sleep()`ed the profile delay and then wrote the whole body (a latency tarpit); the responder dripped 1-3 bytes 20-60 ms apart. One request distinguished them. | Fixed: `deception::DripBody` streams the static body in `chunk_size` pieces with `chunk_delay_ms` gaps, both defaulting to the catalogue's `stream_defaults` (3 bytes, 50 ms), and declares `Content-Length` because the responder does. |
| **Body** | The gateway serves short compile-time static bodies (a 150-byte 403); the responder serves the reviewed `/opt/tarpit/responses/403.html` (3539 bytes, the Apache test page). A client told the two apart by content alone, which contradicts "one fake application". | **Still divergent.** The planned fix is to generate the gateway's bodies from `tarpit/profiles/catalogue.yaml` at build time. Until then this document must not claim body parity. |

The lesson worth keeping: the previous version of this file claimed `a client cannot tell which one
answered`. Nothing measured it. A claim in a contract document is not evidence that the contract is
met, and three of the four fields in it were true.
