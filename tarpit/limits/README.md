# Concurrency and resource ceilings

Written 2026-11-15 from a measured comparison of listener costs on the reference host.

This file is an **index, not a source of truth**. Every value below is owned by the file in its
"Authoritative source" column; restating them here is only useful if this file also says where to go
looking, and says so in a way that goes stale visibly. Each row therefore names the file to read and the
command that reads the live value.

```bash
# responder ceilings, as deployed
ssh agent@lab-web01.lab 'sudo grep -h "max-threads\|per-ip-max" /etc/systemd/system/tarpit-test.service'
# gateway ceilings, as deployed
ssh agent@lab-web01.lab 'sudo grep -hE "max_connections|max_concurrent_drips|max_drip_ms" /etc/fleet-filter-gateway/policy.toml'
```

## The measured number this bundle is built on

A measured comparison at two concurrency levels showed the answer was not the number
the brief assumed:

| Measurement | Result |
|---|---|
| Configured pool | `--max-threads 32` |
| Concurrent slow drips served at 32 | 32, all at ~5 s |
| Concurrent slow drips at 36 | 32 served at ~5 s, **4 rejected immediately with HTTP 503** |
| Normal (non-tarpitted) request latency during the burst | 1.3–2.7 ms, unchanged |
| Apache's own contribution to the ceiling | none — Apache's event MPM was not the constraint |
| **Deployed ceiling before the D fix** | **4**, not 32 |

The last row is the reason H1 needed work rather than just documentation. `BoundedThreadingServer` applied
`per_ip_max` to the **socket peer** rather than to the client identity resolved from a trusted proxy, so
every request arriving through the Stage 2 gateway shared one single 4-connection budget and the
configured `max_threads=32` was unreachable in production. The fix (and the reason the number is now real)
is in `tarpit/server/server.py`, covered by `tests/unit/test_server_concurrency.py` (10 checks).

## Ceiling set

| Ceiling | Value | Owner (authoritative) | Derivation | Enforcement point |
|---|---|---|---|---|
| Responder global threads | `32` | `systemd/tarpit-test.service` → `--max-threads` | measured (D1–D3) | `BoundedThreadingServer` semaphore; excess gets an immediate `503` |
| Responder per client IP | `4` | `systemd/tarpit-test.service` → `--per-ip-max` | configured default, now correctly attributed to the forwarded client for trusted-proxy peers | `TarpitHandler` slot accounting |
| Responder max drip duration | `5` s (`--max-drip`, chunk `3` bytes @ `0.05` s) | `systemd/tarpit-test.service` | measured (B8: 754 bytes in 252 reads of 3 bytes, 5.047 s) | responder write loop |
| Responder max file / body read | `262144` / `65536` bytes | `tarpit/server/server.py` defaults | configured default | responder read guards |
| Gateway connections | `512` | `gateway/policies/lab-web01.toml` → `[limits] max_connections` | configured default | listener accept loop |
| Gateway per source | `16` | `gateway/policies/lab-web01.toml` → `[limits] max_connections_per_source` | configured default | per-source connection accounting |
| Gateway header count | `100` | `gateway/policies/lab-web01.toml` → `[limits] max_headers` | configured default | hyper HTTP/1.1 request parser |
| Gateway header read timeout | `30` s (`0` disables) | `gateway/policies/lab-web01.toml` → `[limits] header_read_timeout_secs` | hyper's documented default, now declared instead of inherited (O6) | hyper HTTP/1.1 parser, armed by `hyper_util::rt::TokioTimer` — measured: a connection that never finishes its headers is closed at 30.01 s instead of being held open indefinitely |
| Gateway inline drip budget | `32` concurrent | `gateway/policies/lab-web01.toml` → `[deception] max_concurrent_drips` | set to match the responder's measured ceiling | `DripBudget` RAII guard; over-budget → local `503` + `x-fleet-filter-deception: budget-exhausted` (58–65 ms) |
| Gateway max drip | `8000` ms | `gateway/policies/lab-web01.toml` → `[deception] max_drip_ms` | configured default | inline response drip |
| Gateway per-connection response cap | `65536` bytes | `gateway/policies/lab-web01.toml` → `[deception] per_connection_max_bytes` | configured default | inline response writer |
| Gateway process memory | `256M` (`MemoryMax`) | `systemd/fleet-filter-gateway.service` | configured default | systemd cgroup |
| Gateway file descriptors | `65536` (`LimitNOFILE`) | `systemd/fleet-filter-gateway.service` | configured default | systemd |
| **Apache file descriptors** | **`1024` soft** (hard `262144`) | *nowhere* — inherited from the default user session, not from `httpd.service` | measured (A7) | kernel; see the gap below |
| Apache MPM workers | *unset* — compiled-in event defaults | *nowhere* — no `<IfModule mpm_event_module>` block exists in the loaded config | measured (A7) | Apache |

## The gap this bundle does not close

Two ceilings on lab-web01 are **inherited rather than declared**, and both are recorded as open follow-ups
owned by the owner rather than by H1:

1. **Apache's soft `Max open files` is 1024** (A7-c). It is the first real limit Apache will hit, well
   before memory, and it is not set by anything in the configuration — so it changes silently whenever the
   service's session defaults change.
2. **No MPM tuning exists at all** (A7-a). `MaxRequestWorkers`, `ThreadsPerChild` and
   `MaxConnectionsPerChild` are all compiled-in defaults, which makes the worker budget unreviewable. The
   brief's central risk was Apache worker exhaustion; on this host the responder pool is the binding
   constraint today, but that is only true while the fd ceiling is what it is.

H1 sets the ceilings the project owns. Those two belong to the host, and moving a shared host's Apache
limits is a change for every vhost on it, so they are left as configured unless an operator
changes them deliberately.

## How a regression would be detected

| Ceiling | Detection |
|---|---|
| Responder global / per-IP | `tests/unit/test_server_concurrency.py` (10 checks, slot accounting) and `tests/load/benchmark_workers.sh` (reproduces the 32-served / 4-rejected split) |
| Gateway drip budget | `tests/gateway/` budget-exhaustion cases; the measured signature is an immediate `503` with `x-fleet-filter-deception: budget-exhausted` instead of a slow response |
| Gateway header read timeout | open a TLS connection, send `GET / HTTP/1.1` plus one header with no terminating blank line, and time the close: it must be the configured number of seconds, not indefinite |
| Any deployed value drifting from the repo | the two `ssh` commands at the top of this file; a deploy that changes a value without changing the repo shows up as a diff between this table and the live output |
