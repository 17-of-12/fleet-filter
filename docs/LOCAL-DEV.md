# Local development stack

Why this file exists: the deployed system lives on two fleet hosts and neither can be exercised
without touching it (SKILL.md "Current deployment state"), so every change used to be validated
against a real deployment rather than against a running copy. This is the working port of the
project onto one loopback box, run by `bin/local-stack.sh`, plus an honest list of what the port
does **not** prove.

## What runs

| Process | Address | Source | Notes |
|---|---|---|---|
| controller store | `var/state.db` | `controller/adaptive-tarpit.py` | renders `var/tarpit-ips.map`; audit log `var/audit.jsonl` |
| real site (stand-in) | `127.0.0.1:9000` | `python3 -m http.server` | `var/www/index.html`; fast, boring, the thing being defended |
| gateway | `127.0.0.1:3001` | native `cargo build --release` | classifies from the rendered map, `--on-quarantined inline`, `--map-ttl 2` |
| responder (Stage 1) | `127.0.0.1:8081` | `tarpit/server/server.py` + `tarpit/profiles/catalogue.yaml` | the Python slow-drip path a host without the gateway runs |
| console | `127.0.0.1:8188` | `web/app.py` over `var/cache.db` | fed by `web/sync.py` from `web/installs.yaml` |

The topology is the deployed one, not a convenience: the gateway fronts the real site and answers a
quarantined client itself, so the slow path under test is the gateway's own bounded inline drip
(`generic;delay_ms=5000`). The Python responder is started beside it because it is the Stage 1 path,
and `verify` measures it directly.

## Run it

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt pytest   # once
bin/local-stack.sh up          # build if needed, start all four, print URLs
bin/local-stack.sh verify      # acceptance test, see below
bin/local-stack.sh sync        # refresh the console cache from the install registry
bin/local-stack.sh status      # pid, port and health of each process
bin/local-stack.sh logs 40     # tail the four logs
bin/local-stack.sh down        # stop everything it started
```

Toolchain: `rustup` toolchain `1.92.0` (default profile, so clippy and rustfmt come with it) and
CPython 3.14 in `.venv`. The Rust version matters - `gateway/Cargo.toml` pins `rust-version =
1.92.0` and `gateway/clippy.toml` declares the same `msrv`, so a different compiler makes a lint
verdict a different claim.

## Acceptance test (`bin/local-stack.sh verify`)

Measured 2026-11-24 on the local port:

```
unmapped  gateway 200 0.004725        # clean client: site answered in 4.7 ms
claimed   127.0.0.1 -> 1              # controller claim, rendered into the map
observed  map change picked up after 2.0s (gateway --map-ttl 2)
mapped    gateway 2.45s (158 byte body in 50 pieces, generic;drip_ms=2450;chunks=50)
responder stage 1 drip 200 5.057999
revoked   127.0.0.1 removed from the map
PASS  unmapped 0.005s, mapped 5.005s (+5.000s), stage 1 drip 5.058s
```

The three assertions are the ones the project exists to provide, and each of them is the *slow*
outcome when it fails:

* The unmapped client is fast. A 4 ms answer on the mapped path is exactly what a broken map
  lookup returns - the 2026-11-13 silent regression - so "fast" is asserted as a ceiling, and
  "slow" is asserted as a floor (more than one second slower than the unmapped path), never as an
  exact number, because a loaded box is not a regression.
* The quarantined client is slowed by the gateway itself, and the response says so in
  `X-Fleet-Filter-Deception` (`generic;drip_ms=2450;chunks=50`). That header is what distinguishes a real
  inline drip from a request that was quietly proxied through.
* Map observation latency is printed, not assumed. `--map-ttl 2` is a development setting chosen so
  the harness answers in seconds; the deployed value (default 300) is a separate decision.

## What this port does not prove

State it before quoting a local result as a fleet claim:

* **No Apache.** The RewriteMap mechanism, `mod_proxy` to the tarpit, vhost scoping and the
  `Protocols h2c` behaviour are all absent. Nothing here can regress or confirm them.
* **No nftables, no Wazuh, no fail2ban.** Both detection planes and the firewall fallback are
  unexercised; only the controller's claim/lease/map path and the gateway's map lookup are real.
* **No TLS.** The gateway runs cleartext, so ALPN, h2 over TLS, certificate handling and the
  hop-by-hop header rules on the TLS path are untested.
* **glibc and Python are newer, not older.** Ubuntu 26.04 / glibc 2.41 / CPython 3.14 against
  Oracle Linux 9.8 (glibc 2.34, python 3.12) and lab-web01's EL 8.10 (glibc 2.28, python 3.9).
  The native gateway binary produced here **cannot run on the fleet** - `bin/build-gateway.sh`'s
  container build remains the only artifact path, and that asymmetry is deliberate, not a gap to
  close.
* **The console reads a real fleet cache.** `web/sync.py` reaches lab-web01 and build01 over SSH,
  so the numbers rendered locally are the deployed ones. That is a read of production, not a
  sandbox; do not point actions at it (`--allow-actions` stays off).

## Deviations found while porting (2026-11-24)

* `web/sync.py` read `state.db` and `audit.jsonl` through `ssh_read_raw` directly, bypassing
  `read_host_file`, so the control node's own state was read over SSH to itself. `test_sync.py`
  passed on build01 only because `ssh agent@build01` happens to work there. Fixed, with the test now
  exercising the local path it claims to test - see
  `data/research/console-local-state-read-2026-11-24.md`.
* `test_sync.py` was the only failing suite of the port before that fix (49/50), and the whole
  suite is green afterwards: `bin/check.sh --all`, both interpreters, 2026-11-24.
