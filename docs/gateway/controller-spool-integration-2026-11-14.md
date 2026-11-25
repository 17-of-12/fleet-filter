# Bundle R - controller spool integration and gateway memoization (R1-R7)

Date: 2026-11-14 (UTC stamp 20261114T181642Z for the deployment backup)
Host: lab-web01.lab (Stage 2 test listener, Profile B)
Commit: 261e1d6 - "Bundle R1-R4: versioned spool schema, gateway classification cache and claim writer"
Prior commit: 88bbc36 (Bundle Q) - the artifact deployed before this change

## What the bundle asked for

Make the Stage 2 gateway a first-class *producer* of quarantine claims without giving it a write
handle on the authoritative store, and make its view of quarantine state cheap enough to consult on
every request. Seven tasks: a versioned claim schema (R1), a durable spool writer (R2), failure
handling that preserves evidence (R3), a client classification cache (R4), an end-to-end latency
measurement (R5), a permission-boundary proof (R6), and roadmap bookkeeping (R7).

## Decisions taken

**The gateway reads the rendered map, not the database.** `--map /etc/httpd/tarpit-ips.map` is the
same artifact Apache consumes. Reading SQLite from a long-running process would have meant either a
write-capable handle (breaks the single-writer rule) or WAL sidecar files owned by root that a
read-only client cannot open - the failure mode already documented for `list` on this host. The map
is one small file, already the enforcement contract, and its TTL is a policy input rather than an
implementation detail.

**Each producer owns a separate spool directory.** The gateway writes
`/var/lib/fleet-filter-gateway/spool` (0750 `fleet-filter-gw:fleet-filter-gw`) instead of sharing
`/var/lib/adaptive-tarpit/spool` (0755 `nobody:nobody`). A shared queue cannot be permissioned per
producer, and a poison file from one producer would be indistinguishable from another's. The
controller timer now drains both.

**`schema_version` is validated, not inferred.** A missing field is read as legacy v1 (that is what
every file written before this change is); any value other than `1` is refused. A future producer
emitting `2` must fail loudly rather than have its fields reinterpreted.

**Detection memoization is deliberately narrow.** Only a *detection* is memoised, and only for
`(ip, claim_key)`. A `Normal` classification is never memoised, because "this address was clean
five minutes ago" says nothing about the request arriving now - the map is re-read on its TTL
instead. The memo's TTL (300s default) matches the spool's per-claim minimum interval, so the two
rate limits cannot disagree.

**Quarantined traffic is still proxied by default.** `--on-quarantined proxy` keeps the current
behaviour (the backend answers, slowly, via the vhost's RewriteMap routing). `reject` and `tarpit`
are implemented and tested but not deployed, because switching the enforcement mode is a separate
decision from wiring the pipeline.

## Deployed state on lab-web01

Backup of everything replaced: `/root/backups/20261114T181642Z-bundle-r/`
(`fleet-filter-gateway.service`, `adaptive-tarpit.service`, `adaptive-tarpit`, `fleet-filter-gateway.bin`).

| Path | Change |
| --- | --- |
| `/usr/local/bin/fleet-filter-gateway` | new binary (EL8 build, artifact `data/artifacts/fleet-filter-gateway-0.1.0-88bbc36.json`) |
| `/etc/systemd/system/fleet-filter-gateway.service` | added `--map`, `--spool`, `--author`, `--detect-prefix` |
| `/etc/systemd/system/adaptive-tarpit.service` | added a second `drain-spool --spool /var/lib/fleet-filter-gateway/spool --render` |
| `/usr/local/bin/adaptive-tarpit` | controller with the versioned schema and `lstat` spool reader |
| `/var/lib/fleet-filter-gateway/spool` | created, 0750 `fleet-filter-gw:fleet-filter-gw` |

Runtime banner after restart (proves the wiring, not just the compile):

```
fleet-filter-gateway 0.1.0 listening on 198.51.100.111:8443 [tls(cert=/etc/fleet-filter-gateway/tls/lab-web01.crt)]
classify detection=/h2probe-
spool dir=/var/lib/fleet-filter-gateway/spool written=0 failed=0 min_interval_s=300 max_entries=10000
policy on-quarantined=proxy
```

## R5 - measured chain latency (`tests/gateway/r_chain_latency.sh`)

Run against client `198.51.100.108` (bound to `lo`, not allowlisted, not previously leased):

| Stage | Epoch | Observation |
| --- | --- | --- |
| baseline | 1794680556 | backend latency for the client before any claim: **0.001395s** |
| gateway | 1794680556 | `GET /h2probe-r5` through `198.51.100.111:8443` -> **404** (proxied, per `on-quarantined=proxy`) |
| spool | 1794680556 | `1794680556-198.51.100.108-prefix__h2probe-.json` written in the **same second** |
| store + render | 1794680603 | map contains `198.51.100.108 1`; map mtime 1794680602 (**+47s**) |
| enforce | 1794680603 | backend latency for the same client: **5.289885s** (slow-drip responder) |
| gateway view | 1794680603 | `detection peer=198.51.100.108 claim=prefix:/h2probe- spool=written` |

**Measured detect-to-enforce: 47 seconds.** The gateway's own classification was correct at t+0
(the memo), the map caught up at t+47s, and Apache's enforcement changed from 1.4ms to 5.29s.

**Worst case, from the deployed timer settings:** `OnUnitActiveSec=5min` + `RandomizedDelaySec=30`
+ `AccuracySec=1min` = **~6.5 minutes** to render, plus Apache's 60-second txt-map cache = **~7.5
minutes** to enforce. The 47s observation is fast only because the timer happened to fire shortly
after the claim; the number to plan around is 7.5 minutes, and that is the cost of the
no-direct-write contract. Tightening it means either a faster timer or a gateway-side enforcement
change (`--on-quarantined tarpit`), which is Bundle S territory.

## R6 - permission boundary (executed as `fleet-filter-gw`)

| Operation | Result |
| --- | --- |
| read `/var/lib/adaptive-tarpit/state.db` | **succeeds** (13 claim rows) |
| insert into `state.db` | **refused** - `OperationalError: attempt to write a readonly database` |
| write `/var/lib/fleet-filter-gateway/spool/r6-probe.json` | **succeeds**, mode 0644 |
| `adaptive-tarpit list --json` as the gateway user | **succeeds** |
| responder spool `/var/lib/adaptive-tarpit/spool` still writable by `nobody` | **succeeds** (unchanged) |

The gateway can observe quarantine state and submit claims; it cannot mutate the store. A control
insert as root succeeded and the row was removed afterwards (row count back to 13).

## Tests

| Suite | Runtime | Result |
| --- | --- | --- |
| `bin/test-gateway.sh` (cargo test, EL8 builder image) | rustc 1.92.0 / glibc 2.28 | 17 passed (9 spool, 8 classify) |
| `tests/unit/test_spool.py` | python3.12 and python3.9 | 26 checks, 0 failures (both) |
| `tests/unit/test_ingest.py` | python3.12 | 72 passed, 0 failed |
| `tests/unit/test_docstrings.py` | python3.12 | 136 functions, 0 findings |
| `tests/unit/test_render_rules.py` | python3.9 | 40 passed, 0 failed |
| `tests/unit/test_signatures.py` | python3.9 | 29 checks, 0 failures |
| `tests/security/test_input_hardening.py` | python3.12 | 93 passed, 0 failed |

`bin/test-gateway.sh` is new: it runs `cargo test` in the same Oracle Linux 8 builder image the
artifact is built from, so the tests execute against the target glibc rather than the host's.

## Gaps and follow-ups

- **Detection surface is still a prefix list.** `--detect-prefix /h2probe-` is the interim rule set;
  Bundle S replaces it with `signatures.yaml`-derived policy so the gateway and Apache consult one
  vocabulary.
- **A failing responder drain blocks the gateway drain for that run.** The timer runs
  `expire`, then the responder drain, then the gateway drain; a non-zero exit from the middle
  command stops the rest. That is intentional (a poison file should be visible, not swallowed) but
  it couples the two producers until Bundle S gives each queue its own timer.
- **`--on-quarantined` is not exercised in production mode.** `proxy` is deployed; `tarpit` and
  `reject` are unit-tested and were verified locally during development, but switching modes on
  lab-web01 is a separate decision.
- **Gateway-side TLS session reuse** is unchanged by this bundle, so the ~52ms fresh-handshake
  latency measured in Bundle P still dominates per-request cost for clients that do not reuse
  connections.
