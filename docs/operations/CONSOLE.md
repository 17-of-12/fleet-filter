# Fleet Console (`web/`)

**Bundle Y** · deployed on `build01.lab` · owner decision 2026-11-15 placed the console on the
control node rather than on a protected host.

The console answers one question — *what is deployed where, what has been detected, and what is the
trend* — across every registered Fleet Filter host, without becoming part of any request path. It is a
window onto controller state, not a controller.

## Why it is on build01 and not on a protected host

A console that sits on a protected host becomes a second thing that has to be right for that host to
serve traffic. On build01 it is a reader only. This was verified rather than asserted: with the console
running, `lab-web01:80` answered `403 in 0.008198s`; with the console process stopped, `403 in
0.009481s`, and no file in `/etc/adaptive-tarpit`, `/etc/fleet-filter-gateway`, or any systemd unit on
lab-web01 names build01. A host keeps enforcing exactly as configured whether or not the console is up.

## Deployment layout

| Path | Owner / mode | Role |
|---|---|---|
| `web/app.py` (repo) → `/home/agent/projects/Fleet-Filter/web/app.py` | `agent` | The HTTP application. Stdlib only; no framework, no WSGI server. |
| `web/sync.py` (repo) | `agent` | Collects each registered host's controller state into the cache. |
| `web/installs.yaml` (repo) | `agent` | The registry of hosts the console knows about. Source of truth for the Installs page. |
| `systemd/fleet-filter-ui.service` → `/etc/systemd/system/` | `root` | Runs the app as `agent` on `127.0.0.1:8735`. |
| `apache/fleet-filter-ui.conf` → `/etc/httpd/conf.d/` | `root:root 0644` | Apache vhost on `*:8188`, TLS: authentication plus `ProxyPass` to the app. |
| `/etc/fleet-filter-ui/htpasswd` | `root:apache 0640` | bcrypt credential store for the `admin` user. |
| `/root/.fleet-filter-ui-admin-password` | `root 0600` | The plaintext password, kept readable so it can be handed out without regeneration. |
| `/var/lib/fleet-filter-ui/cache.db` | `agent:agent 0600` | The SQLite cache the app reads. |
| `/var/log/httpd/fleet-filter-ui-access_log` | `root` | Console traffic only, separate from the host `access_log`. |

**Published surface:** `https://build01.lab:8188/` (firewalld port `8188/tcp` opened
2026-11-15; the app's own `127.0.0.1:8735` socket is not reachable off-host).

### Transport security (PTN-04)

The listener is TLS, and it has to be. The console authenticates with HTTP Basic, which resends
`username:password` on **every** request rather than once at login, so on a plaintext listener the
password crossed the network in clear text on every page load — and `8188/tcp` is published in
firewalld's public zone. The vhost now presents the host's own certificate
(`/etc/pki/tls/certs/build01.lab/server.crt`, SAN `build01.lab`, the same pair
`:443` uses), so rotating that certificate rotates both surfaces together.

Two consequences an operator needs to know:

- **The port is TLS-only, not plain-with-a-redirect.** Apache 2.4 requires every `VirtualHost` on one
  IP:port to agree on `SSLEngine`; a mixed plain/TLS `:8188` answers the plaintext half with a
  protocol error rather than a redirect. `http://…:8188/` therefore returns `400`, by design.
- **Clients must expect a name mismatch when they connect by IP.** The certificate is issued for
  `build01.lab`; `curl -k` and the capture tool's `ignoreHTTPSErrors` cover that, and
  neither is evidence of a certificate problem. Verify the certificate by fingerprint against
  `/etc/pki/tls/certs/build01.lab/server.crt`, not by the connection's success.

`Strict-Transport-Security: max-age=31536000` is set with `env=HTTPS`, so the promise is only made on
connections that actually were TLS.

### Identity

The service runs as `agent`, not as a dedicated unprivileged user. That is a deliberate deviation from
the `fleet-filter-gw` pattern used on lab-web01: `web/sync.py` authenticates to every registered host
with the `agent` SSH key, so a separate console user would need its own delegated read key before the
sync path would work. Until that delegation exists, the console inherits `agent` and the unit documents
the reason. `ProtectSystem=strict` with `ReadWritePaths=/var/lib/fleet-filter-ui` bounds what the
process can write despite running as the service account.

## Authentication

Apache performs authentication; the application has none of its own.

- `AuthType Basic`, `AuthName "Fleet Filter console"`, `AuthUserFile /etc/fleet-filter-ui/htpasswd`,
  `Require valid-user` on `Location /`.
- `Location /health` is `Require all granted` so monitoring can probe the application without holding
  credentials. It answers the app's `/health`, not Apache's own liveness, so it reports the thing that
  actually serves the console.
- Unauthenticated requests to anything else return `401`; authenticated requests are logged with the
  username in the vhost access log (`10.30.72.218 - admin [...] "GET / HTTP/1.1" 200 11376`).

Rotate the password with:

```bash
PW=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | cut -c1-20)
printf '%s\n' "$PW" > /root/.fleet-filter-ui-admin-password
chmod 0600 /root/.fleet-filter-ui-admin-password
htpasswd -Bbc /etc/fleet-filter-ui/htpasswd admin "$PW"   # -b batch, -B bcrypt, -c recreate
```

`-c` truncates the file, so it is only correct while `admin` is the sole user; add further users by
dropping `-c`.

## Routes

| Route | Purpose |
|---|---|
| `/` | Dashboard: KPI tiles (hosts, active claims, detections by day), a sparkline of detections, and recent audit activity. |
| `/installs` | Every registered host with its stage, address, notes, and whether its state was collected successfully. |
| `/detections` | Claims and audit history: which address, which verdict, which source, when it expires. |
| `/containers` | Container runtime inventory per owned host: runtime names and versions, every container with its state, this project's image tags with digests and sizes, and `system df` storage per runtime. Sourced from `bin/container-inventory.py`. |
| `/webtree` | Stage 4 file audit per owned host: the docroot audited, the scan mode, the clean/review/quarantine counts, and every flagged file with its score, size, mtime, and the reasons that produced the verdict (shape metrics plus any yara rule that fired). Sourced from the report `bin/webtree-audit.py` writes on the host; the console never runs an audit itself. |
| `/reports` | Text/JSON exports of the current cache for offline review or attachment to a ticket. |
| `/api/stats` | The same numbers the dashboard renders, as JSON, for other tooling to consume. |
| `/health` | Liveness plus cache freshness: `{"cache": true, "last_sync": ..., "service": "fleet-filter-ui", "status": "ok"}`. Unauthenticated. |

## Data sources and the sync contract

The app reads **one** file: `/var/lib/fleet-filter-ui/cache.db`. It never queries a remote host during a
request, which is what keeps console latency independent of fleet reachability.

`web/sync.py` rebuilds that cache:

1. Read `web/installs.yaml` for the registered hosts.
2. For each host reachable over SSH, read (never write) the controller's `state.db` and `audit.jsonl`
   with `ssh -o BatchMode=yes -o ConnectTimeout=8 <user>@<host> cat <file>`.
3. Build a fresh cache in a temporary file **beside the cache itself**, then `os.replace()` it over the
   live one, so a reader never observes a half-written database. Beside it and not in `/tmp` because
   `os.replace` cannot rename across a mount: the first timer-driven run failed with `EXDEV` under the
   sync unit's `PrivateTmp=yes`, where `/tmp` is a tmpfs and `/var/lib/fleet-filter-ui` is not.
4. Record `meta.last_successful_fetch` and the content hash of the snapshot, so a later run can
   distinguish "nothing changed" from "the fetch failed".

Tables: `meta` (sync bookkeeping), `installs` (registry rows), `claims` (active leases per host),
`audit_events` (controller audit lines, `ts` normalised to unix seconds and `event` mapped to `action`).

Current state, measured 2026-11-15: `registered 12 hosts, queried 1, 4 claims, 32 audit events,
0 error(s)`. One host is queryable because only lab-web01 runs a controller today; the rest are
registered as candidates, which is the honest shape of the fleet until rollout proceeds.

### Cache freshness (the sync timer)

The console shows what was last synced, not what is true now, so freshness is a scheduling problem and
it belongs to `fleet-filter-ui-sync.timer` / `.service`, not to the app:

| Unit | Role |
|---|---|
| `fleet-filter-ui.service` | serves the console on 127.0.0.1:8735 (Apache fronts it on 8188) |
| `fleet-filter-ui-sync.timer` | fires every 15 min (`OnBootSec=2min`, `OnUnitActiveSec=15min`, 90 s jitter) |
| `fleet-filter-ui-sync.service` | one-shot `web/sync.py` run that rewrites `cache.db` |

**Why 15 minutes.** A sweep opens one SSH session per registered host - 8 s `ConnectTimeout` each for
the ten that do not answer today, so roughly two minutes of work - and the console's own staleness
indicator only turns amber after an hour. Anything faster spends SSH capacity refreshing a number
nobody reads more often than hourly; anything slower lets the dashboard go amber between operator
checks. The interval is one line in the timer unit, and the first measured run after it was enabled
brought the reported cache age from 8 h 34 m down to 11 s.

**Failure behaviour.** A failed sync must not stop the timer and must not blank the console: the app
keeps serving the previous cache (the stale-on-error rule in `docs/FLEET-STATE.md`) and the next tick
retries. `TimeoutStartSec=300` kills a genuinely hung sweep so it cannot stack processes on the
console. This is the path that surfaced the `EXDEV` defect above - the unit failed on its first run
while the identical command run by hand had always worked, which is the general lesson: a systemd unit
is a different environment, and testing only by hand hides that.

### Relationship to the fleet store

`docs/FLEET-STATE.md` specifies the shared threat-intelligence store on build01 keyed by
`(subject_ip, authoring_host)`. The console cache and that store are **different artefacts with
different jobs**: the cache is a rendered read model for a UI, the store is the authoritative claim set
that hosts publish to and merge from. Building the store does not replace `cache.db`; the console becomes
one of its readers.

## Failure modes

| Failure | What the console does | What served traffic does |
|---|---|---|
| A registered host is unreachable | `installs` row is marked failed, previous cached rows for that host are retained, sync reports the error and continues with the other hosts. | Unaffected. |
| `cache.db` missing | `/health` reports `cache: false`; pages render empty rather than erroring. | Unaffected. |
| The app process dies | Apache answers `502` for authenticated requests; `systemd` restarts it (`Restart=on-failure`, `RestartSec=5`). | Unaffected. |
| Apache dies | Console unreachable on `:8188`; the app still answers on `127.0.0.1:8735`. | Unaffected — the console is not in the request path of any vhost. |
| Sync has never run | Dashboard shows zero hosts and `cache: false` rather than a stale number presented as current. | Unaffected. |

## Operating commands

```bash
systemctl status fleet-filter-ui.service          # app process
systemctl reload httpd                             # after editing apache/fleet-filter-ui.conf
sudo apachectl configtest                          # always before reload
.venv/bin/python web/sync.py                        # manual refresh of the cache
curl -k -u admin:$(sudo cat /root/.fleet-filter-ui-admin-password) https://127.0.0.1:8188/api/stats
journalctl -u fleet-filter-ui.service -n 50        # app log
sudo tail -f /var/log/httpd/fleet-filter-ui-access_log
```

## Visual capture and regression

**Standing rule (owner, 2026-11-16): any GUI work ships with vision inspection.** A change to the
console's markup, CSS, or rendered data is not verified until the affected routes have been captured
and the screenshots actually read. DOM assertions and `curl` checks are not sufficient - the first
vision pass found a bar chart whose markup, CSS and computed `width:95%` were all correct and which
rendered no bar at all, a class of defect that only exists in the rendered page.

`web/tools/capture-console.mjs` renders every route at desktop and mobile viewports with Playwright
and writes the PNGs plus a `manifest.json` (HTTP status, bytes, sha256 per capture) under
`data/artifacts/console-<UTC date>/`:

```bash
node web/tools/capture-console.mjs --password "$(sudo cat /root/.fleet-filter-ui-admin-password)"
node web/tools/capture-console.mjs --routes /,/installs --viewports 1440x900 --out /tmp/shots
```

Two things the tool exists to get right:

- **Authentication must be `context.setHTTPCredentials`, not URL userinfo.** `http://admin:pw@host:8188/`
  returns 401 against this Apache vhost, which is why earlier screenshot attempts produced error pages
  instead of the app. Playwright's context credentials put a correct `Authorization` header on every
  request, subresources included.
- **Playwright is a global module, so import it through `createRequire`.** ESM resolution ignores
  `NODE_PATH`, so `import { chromium } from "playwright"` fails from inside the repo; the script
  resolves it with `createRequire(import.meta.url)` (override with `PLAYWRIGHT_MODULE`).

The manifest's sha256 per route is what makes a later run comparable: a changed hash means the
rendered page changed, and the recorded status catches a route that started erroring without looking
obviously different. Results of the first vision-assisted pass: `data/results/console-visual-audit-2026-11-16.md`.

## Write path (Bundle Y2)

The console can now set a host's emergency bypass — `adaptive-tarpit bypass on|off --ttl` — from the
Installs page. It is gated, not default:

- **Enabled by flag.** `--allow-actions` (or `PT_UI_ALLOW_ACTIONS`) turns the write path on; with the
  flag off the app renders no controls and answers any POST with `403` and an explanation. The code
  lives in `web/actions.py`, a separate module so "read-only by default" is a property of the import
  graph rather than a convention: `web/app.py` only reaches it when the flag is set.
- **Validated before it is executed.** The target must be in the registry, `state` must be `on` or
  `off`, `on` requires a TTL between 60 s and 7 days and a reason, and every value is `shlex`-quoted
  before it reaches the remote shell. A rejected request never opens an SSH connection — asserted by
  `tests/unit/test_actions.py` (33 checks, Python 3.9 and 3.12).
- **The actor is the authenticated user.** The controller's audit line records who disabled
  enforcement, so the console must know who called it. Apache's `RequestHeader set X-Forwarded-User
  "%{REMOTE_USER}e"` turned out to write the literal string `(null)` whenever `REMOTE_USER` is unset,
  which the first live test caught as `"actor": "(null)"` in `bypass.json`. Two fixes: the vhost now
  guards the directive with `env=REMOTE_USER`, and `authenticated_user()` ignores the placeholder and
  falls back to decoding the forwarded `Basic` credential. An action taken with no identity at all is
  refused rather than recorded as `anonymous`.

Live verification (2026-11-15, through Apache as `admin`): `POST /actions/bypass` with
`state=on&ttl=600&reason=console Y2 verification` returned 200 and produced on lab-web01
`{"actor":"admin","event":"bypass","expires_at":"2026-11-15T16:11:34Z","host":"lab-web01.lab",
"reason":"console Y2 verification","schema":1,"state":"on","ttl":600}` in `audit.jsonl`; a following
`state=off` cleared it and `adaptive-tarpit verify` passed.

## Open work (Bundle Y)

Bundle Y is complete: Y0 (build), Y1 (deployment), Y2 (bypass toggle) and Y3 (this document), plus Y4
(the console audit in `data/results/console-visual-audit-2026-11-15.md`). See `TODO.md`, Bundle Y,
for the per-task evidence.
