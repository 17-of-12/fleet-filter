# Response profiles and the deception identity (Bundles I1, I2, I4, and the B9 pairing)

One file answers three questions at once: **what fake thing does the tarpit show** (I1), **which
fake thing does *this* request get** (I2), and **is the fake thing the same on every host** (I4).
Bundle B9's per-variant `verdict_to_report` is the fourth answer: **does the response claim the
vulnerability is present or absent.**

| Artifact | Role |
|---|---|
| `tarpit/profiles/catalogue.yaml` | the A–G catalogue, the shared identity, per-vhost/path selection |
| `tarpit/profiles/bodies/*` | the fabricated bodies (one per profile) |
| `tarpit/server/profiles.py` | loader + validator + `select()` used by the responder |
| `tarpit/server/server.py` | `--profiles` / `--signature-store`, and the response media type |
| `controller/signatures/signatures.yaml` | per-variant `response_profile` + `verdict_to_report` (B9) |
| `tests/unit/test_profiles.py` | 38 checks on Python 3.9 and 3.12 |

## I1 — the seven strategies, now as data

The original design brief names seven response strategies. `tarpit/profiles/` was an empty directory
with a `.gitkeep`; it now holds the catalogue and the bodies.

| Profile | Handoff name | Body | Media type |
|---|---|---|---|
| A | Slow fake configuration | `bodies/A.env` | `text/plain` |
| B | Slow Git repository metadata | `bodies/B.git-config` | `text/plain` |
| C | Fake administrative website | `bodies/C.admin.html` | `text/html` |
| D | Slow error response | `bodies/D.error.html` | `text/html` |
| E | Slow JSON/API response | `bodies/E.api.json` | `application/json` |
| F | Delayed headers and progress | `bodies/F.delayed.txt` | `text/plain` |
| G | Controlled redirect maze | `bodies/G.maze.html` | `text/html` |

Every body is fabricated: no real repository names, no internal addresses, no real people (handoff
§12.5, synthetic credentials only). Streaming shapes (`min/max_chunk_bytes`, chunk delays, duration
cap) live in the catalogue too, so retuning the fingerprint is a config change rather than a code
change, and the gateway and the responder can be compared against one set of numbers.

### How streaming is actually applied (and the month it was not)

`profiles.stream_for(catalogue, profile_id, rng=None)` resolves the streaming shape for the profile
`select` chose: `profiles_stream_overrides[profile]` merged over `stream_defaults`, returning
`{chunk_size, chunk_delay, max_drip}` in the units `TarpitHandler` uses, or `None` when the catalogue
predates streaming (the handler then keeps its own constants rather than being silently respeeded).
`server.py` threads that value from `_resolve` through `_serve` into `_drip`, so the duration logged
for a response and the bytes written to it come from one decision.

This existed because the I3 evaluation measured the alternative. The catalogue declared the shapes but
nothing read them: the responder dripped with its own compiled `chunk_size = 3`, `chunk_delay = 0.05`,
`max_drip = 5.0`, so every profile's duration was a function of body size alone. Profile F - whose
override promises 120-400 ms delays and an 8 s cap - measured 2.769 s, exactly `min(5.0, 0.05 x 56)`
from the generic formula. `data/results/i3-profile-engagement-2026-11-16.md` records it; the tests in
`tests/unit/test_profiles.py` now pin both failure modes (an override not applied, and a shape that
cannot be served being accepted).

Two deliberate decisions, because "the config is read" still leaves questions open:

- **One draw per response, not per chunk.** The catalogue states ranges, so a chunk size and a delay
  are drawn once (`rng` is a parameter so tests can seed it). Drawing per chunk would be marginally
  more organic and would make the logged duration stop describing the response that was sent.
- **`max_response_bytes` is validated but not authoritative.** Body size is enforced by the
  responder's `--max-body-bytes`, which also bounds responses served outside the catalogue; letting a
  per-catalogue value override it would change behaviour for bodies the catalogue never selected.

## I4 — one identity, and the vocabulary problem it fixes

The identity is declared once in the catalogue:

```yaml
identity:
  application: campus-portal
  version: "2026.11.4"
  build: "2026.11.4+sha.9f2c1d"
  server_header: "Apache/2.4.37 (Oracle Linux Server) OpenSSL/1.1.1k"
  x_powered_by: "PHP/7.2.34"
```

`server_header` is deliberately identical to what lab-web01's real Apache answers — the cheapest way
to be caught lying is a `Server` header that disagrees with the site next door. The responder reads
the charset from the same block instead of hard-coding `UTF-8` in the response writer.

The part that was actually broken: **three components had three vocabularies for the same
profiles.** `signatures.yaml` said `generic_slow` / `slow_error` / `slow_400` / `slow_404_app_shaped`,
`gateway/src/deception.rs` says `generic` / `exploit-probe` / `api-probe`, and the handoff says A–G.
Nothing checked that they agreed. The catalogue now owns the mapping through `aliases`, and
`tests/unit/test_profiles.py` fails if (a) a name used in `signatures.yaml` resolves to nothing, (b)
an alias is claimed by two profiles, or (c) one of the gateway's three profile names is not resolvable.

One subtlety the alias table had to solve: `slow_400` and `slow_404_app_shaped` are both "profile D"
but must answer **400** and **404** respectively. A plain alias would silently rewrite a 400 into a
404 — and a scanner that sent a malformed request and received a well-formed 404 has learned
something again. Hence `alias_status`, which pins the status an alias answers with.

## I2 — selection preserves the request's own context

`profiles.select()` resolves in a fixed priority order and reports which rule fired:

1. **`signature`** — the matched signature's `response_profile` (the B9 pairing). An exact exploit
   request gets the answer that exploit expects.
2. **`path_prefix`** — the longest matching entry in `selection.prefixes`, so `/api/students.json`
   is an API request (E) and `/ldap/` is the admin app (C) even when no signature named them.
3. **`default`** — the vhost default (A).

The `reason` field is machine-readable for the same reason the H4 ladder carries reason codes: the
answer should be explainable after the fact, not inferred from a body.

Before this, `_resolve()` could only serve the per-status reviewed body (or, with `--read-docroot`,
live application bytes). It now consults the catalogue first and **degrades rather than fails**: if
the catalogue cannot answer, the old resolution path serves the request, because a profile defect
should cost plausibility, not availability. A catalogue that *fails to parse* at startup is a
different case — the service refuses to start, since half-configured deception is the failure the
catalogue exists to prevent.

## B9 — `verdict_to_report` per variant

`signatures.yaml` carried `verdict_to_report` at the CVE level while its variants declare different
responses, so a variant answering 404 inherited a CVE-level claim of `vulnerable`. Every variant now
declares its own, and the value has to agree with the status the paired profile emits:

| Variant | `response_profile` | `verdict_to_report` | Why |
|---|---|---|---|
| `probe_path` | `slow_404_app_shaped` (D) | `absent` | the response is a 404; claiming "vulnerable" while returning 404 is the lie that gets caught |
| `h2c_preface_on_http1_only` | `slow_400` (D) | `absent` | a 400 reports nothing installed |
| `bodyless_ct` | `generic_slow` (A) | `vulnerable` | the `.env` answer is the honeypot answer |
| `connect_ct` | `generic_slow` (A) | `vulnerable` | same |
| `filler_headers` | `generic_slow` (A) | `vulnerable` | same |
| `framing_only_shapes` | `generic_slow` (A) | `vulnerable` | declared even though the variant is disabled |

The responder reads the pairing with `--signature-store` and applies it through `select()`. The
lookup is optional by design: a responder on a host without PyYAML keeps working from path-based
selection instead of refusing to start, because the pairing improves the answer and is not what makes
the service alive.

## Deploying

```
tarpit-test.service ExecStart=/usr/bin/python3.9 /opt/tarpit/server.py ... \
    --profiles /opt/tarpit/profiles/catalogue.yaml \
    --signature-store /usr/local/share/doc/fleet-filter/signatures.yaml
```

`--profiles` is empty by default, so an existing deployment is unaffected until it opts in.

## Verification

`tests/unit/test_profiles.py` — **38 checks, passing on Python 3.9 and 3.12** — covers catalogue
validation (schema, identity, every body file present, duplicate aliases, unknown selection targets,
bad `alias_status` keys), all seven profiles, the full alias table, the B9 pairing read from the real
signature store, and every selection rule. `./bin/check.sh --python` passes.
