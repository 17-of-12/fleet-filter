# Drupal runbook

## Versions and images

- `docker.io/library/drupal:11.4.x` ships the `/opt/drupal/web` docroot layout (`/var/www/html`
  is a symlink to it). Confirm the layout from the image before placing files: it is what the
  `web/modules/x.php` class of paths depends on.
- Drupal advisories enumerate exact ranges with `lessThan` semantics (SA-CORE-2026-017:
  0.0.0..10.6.22, 11.0.0..11.3.22, 11.4.0..11.4.13). **The fix and the mitigation are different
  documents on this product**: a fixed release can keep the vulnerable route reachable. Check the
  advisory's *mitigation* section, not only the version line, before concluding a patched
  installation is not exploitable.

## Preconditions the advisory assumes

- **The site must be *installed*.** An uninstalled `drupal` image serves the installer trivially -
  that is what an empty site is - and proves nothing about installer-state bugs. Install properly
  before testing: the image's canonical `dr install` cannot take a `--db-url` and refuses a docroot
  that already has a `settings.php`, so go through drush (installed via the
  `/usr/local/bin/composer` the image ships):
  `composer create-project drush/drush && drush site:install standard --db-url=... -y`.
- **Database pool size is a reproduction parameter** for reinstall-race exploits: the Fail2Install
  write-up measured ~12% re-entry per request only with the pool saturated (25-connection MariaDB).
  A default pool makes their exploit rare, not absent.
- The stock `.htaccess` deny on non-core `.php` files only inspects the URL's tail:
  `/modules/x.php` → 403 but `/modules/x.php/core/x.php` → 200 *and executes*. Unchanged in the
  fixed releases - if a test relies on file placement, test both spellings.

## Build

```bash
lab/drupal-132165/provision.sh          # the record of the exact podman + drush commands
```

Run the same provisioning against a second database for the fixed twin (`11.4.13`) - for this CVE
the pair measures that the fix does not remove the reachable installer, which is what makes the
gateway rule (not the vendor patch) the thing that stops reachability.

## Verification

- The request that proves it: `GET /core/install.php?langcode=en&profile=standard` on the
  *installed* site answers 200 `Drupal already installed` - anonymous, on a site that finished
  installing. The vendor's check set adds `curl -I /core/install.php` and
  `curl -I /core/install.php/foo`; the root `/install.php` answers the site's own 301 to the core
  location (capture it without `-L` - the 301 *is* the finding).
- The negative control for file-placement claims: the same file directly (`403`) vs through the
  PATH_INFO path (`200` + body).

## Putting the gateway in front of it (this host)

```bash
# start the listener on the rendered policy, detached from the session's shell
setsid nohup ~/.cache/fleet-filter-gateway/target/release/fleet-filter-gateway \
  --policy var/deploy/policy.toml > var/deploy/gateway.log 2>&1 < /dev/null &
# record the pid from the process line, not from $!:
echo "$(pgrep -f "^$HOME/.cache/fleet-filter-gateway/target/release/fleet-filter-gateway --policy var/deploy/policy.toml$")" \
  > var/deploy/gateway.pid
bin/gateway-reload.sh --pid var/deploy/gateway.pid --log var/deploy/gateway.log
# expect: gateway-reload: confirmed: policy reload: unchanged (policy version=... sha256=...)
```

`journalctl -u fleet-filter-gateway` prints `-- No entries --` on this host: there is no such unit, so
the log file is the only reload evidence (measured again 2026-11-28).

## Walls

- **A patched twin answers identically.** If you expect the fixed release to 404 the installer, you
  will record a false "not vulnerable": the fix closes the reinstall race, the route keeps serving
  (measured on 11.4.12 and 11.4.13 side by side).
- `dr install` failing on "already has a settings.php" is not a broken image - it means a previous
  install left state; an installed site answering `/core/install.php` is the CVE's premise, not a
  misconfiguration.
- The full exploit needs the DB pool race; a single request without the flood gets "Drupal already
  installed", not the reinstall form. That response is the attack surface, not a null result - the
  race frequency is the exploit's delivery rate, and the missing-authentication class stands without
  it.
- **`setsid nohup cmd &` lies about its pid.** `$!` (and a loose `pgrep -f`) returns the `setsid`
  wrapper, which exits once it has forked; the gateway is alive on the port while `gateway-reload.sh`
  says `kill: (2397096) - No such process`. Take the pid from the exact binary+policy command line (or
  from `ss -ltnp`). Measured 2026-11-28; the plain `nohup cmd & echo $!` form is fine.
- **A listener started by an agent session dies with it.** This host has no `fleet-filter-gateway`
  unit, so a gateway started from a worker session's shell is in that service's cgroup and gets
  SIGTERM'd when the session ends - the deployment record then quotes a dead pid (the 16:38Z session's
  pid 2361824 was gone 40 minutes later, port 8806 closed, `curl` returning `000`). Before quoting or
  trusting a deployment row: `kill -0 $(cat var/deploy/gateway.pid)` and `ss -ltn | grep 8806`, then
  restart and re-verify rather than inheriting the claim.
- **Rendering the quarantine map needs directory write, not file write.**
  `/etc/fleet-filter` was `drwxr-x--x root:root` with a 644 `quarantine.map` owned by the gateway
  user: the gateway could *read* the map, but `adaptive-tarpit.py` renders with
  `tempfile.mkstemp(dir=...)` + `os.replace`, which needs `w` on the directory - it fails `EACCES`
  however the file itself is owned. `chown` on the file and `chmod o+x` on the directory (the two
  earlier fixes) do not cover it; the working form is `sudo -n chgrp operator /etc/fleet-filter &&
  sudo -n chmod 1775 /etc/fleet-filter` (root stays owner, sticky keeps group members from clobbering
  each other's files).
- **A session recorded without a drain still prints claims.** `bin/lab-session.py` runs the spool
  drain only when the probe list contains a group named `after`; without one, the spool is snapshotted
  and the map stays empty, so a manifest can say "the spool and the map round-trip" while the map is 0
  bytes (that is what PR #30's record said). Record the `after` group (or run the drain) whenever the
  entry's evidence claims the map was written.
- **`source=` in the response header names where the class came from.** `map`, `stale-map` (older than
  `map_ttl = 300`) and `memo` are different answers; an unlisted source reads `normal;source=map`, a
  listed one reads `tarpitted;source=map`, and a source the gateway still remembers reads `source=memo`.
  The 403 the 20261128T175315Z session captured for a listed source (`bodies/006.headers`) reads
  `X-Fleet-Filter-Class: tarpitted;source=map` with
  `X-Fleet-Filter-Deception: generic;drip_ms=2600;chunks=53` - `quarantined` is a deception value, not
  a class, and an earlier draft of this line called the class `quarantined`. Quote
  the header verbatim instead of the shape you expect - and wait out `map_memo_ttl` (`--settle`) before
  crediting a quarantine to the map.
- **An empty `raw/` cannot be committed, so do not list it as an artifact.** `bin/lab-session.py`
  creates `bodies/`, `raw/`, `spool/` and `victim/` in every session dir, but `raw/` only receives
  files for probes that carry raw bytes (an HTTP/2 preface, a malformed request line). A session of
  ordinary requests leaves it empty, git drops the empty directory from the commit, and a manifest
  that names `raw/` then points at nothing in the tree - name what the commit carries, and keep the
  run's own dir on disk.
- **Any store edit invalidates every policy hash on the branch, comment-only edits included.** The
  rendered policy stamps `store_sha256:` in its `[detection]` header, so a fix that only touches a
  comment in `controller/signatures/signatures.yaml` still moves the hash of every topology render and
  of `var/deploy/policy.toml`. A concurrent commit changed the store on `origin/main` while this branch
  was open: the branch's pins (`85678c6a` from store `281d3690`) went stale under it and the drift
  guard in `check.sh` fails until all three topologies *and* the host policy are re-rendered from the
  new store and the manifest's quoted hashes follow. So: fetch `origin/main` before releasing, and if
  it moved, re-render, reloaded the listener, and record the session *after* the re-render - a session
  recorded on the superseded render proves nothing about the policy the new commit ships. Re-render
  with the arguments the shipped examples were built from (`tests/unit/test_topologies.py`
  `EXAMPLE_INPUTS` is the source of truth for `deploy/topologies/*`); rendering with the wrong `--host`
  is a content diff, not a stamp diff.
