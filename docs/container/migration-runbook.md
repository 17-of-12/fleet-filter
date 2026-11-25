# Stage 3 container canary — migration runbook and risk register (Bundle W6)

Host: `lab-web01.lab` · Profile: **C** (Stage 3 + Stage 2 + Stage 1) · Written 2026-11-14.
Scope: the canary only. The native Apache on :80/:443 and the Stage 2 gateway on :8443 keep serving
through every step below; nothing here changes what the fleet's users see until Bundle X.

## 1. Prerequisites (all verified on 2026-11-14)

| Check | Command | Required result |
|---|---|---|
| Runtime pinned | `podman --version` | `4.9.4` (the version `container/config.yaml` pins) |
| Compose | `podman-compose --version` | `1.0.6` (EPEL) — note it ignores `pids_limit` |
| Staging tree current | `container/preflight.sh` in `/opt/fleet-filter-container` | exits 0 |
| Image present | `podman images localhost/fleet-filter-apache` | tag matches the repo artifact in `data/artifacts/` |
| Native service healthy | `curl -H 'Host: lab-web01.lab' http://127.0.0.1/ai.html` | 200, md5 matches `/var/www/html/ai.html` |
| Source not quarantined | `awk '$1=="127.0.0.1"{print $2}' /etc/httpd/tarpit-ips.map` | `0` (allowlisted) |

## 2. Deploy / re-deploy

```bash
# from the control node, after any change under container/
.venv/bin/python bin/render-container-compose.py            # regenerate compose.yaml + hash
tar -C . -cf /tmp/stage.tar container bin && scp -q /tmp/stage.tar agent@lab-web01.lab:/tmp/stage.tar
ssh agent@lab-web01.lab 'sudo -n tar -xf /tmp/stage.tar -C /opt/fleet-filter-container'
# on the target
ssh agent@lab-web01.lab 'cd /opt/fleet-filter-container && sudo -n bin/preflight.sh' || exit 1
ssh agent@lab-web01.lab 'cd /opt/fleet-filter-container && sudo -n bin/build-container-apache.sh --git-sha <sha>'
ssh agent@lab-web01.lab 'cd /opt/fleet-filter-container && sudo -n podman-compose -f container/compose.yaml up -d --force-recreate'
```

Preflight failure is a stop condition, not a warning. It checks host identity, SELinux state against
the project toggle, runtime version, every mount source, the published port, and that the compose
artifact was rendered from the config it sits beside.

## 3. Verify (the four suites, all runnable from the control node)

```bash
bash tests/container/test_preflight.sh      # 7 checks  - every SELinux branch + artifact staleness
bash tests/container/test_containment.sh    # 12 checks - W1 live source, W2 read-only, W4 containment
bash tests/container/test_vhost_parity.sh   # 20 checks - W3 surface parity across the three listeners
bash tests/container/test_rollback.sh       # 5 checks  - W6 tested rollback and re-creation
bash tests/container/test_performance.sh    # W5 baseline (refuses to run against a quarantined source)
```

Current results: preflight 7/7, containment 12/12, vhost parity 20/20, rollback 5/5, and the W5
baseline (`native p50 0.39 ms`, `gateway backend 0.37 ms`, `canary 0.35 ms`; 10-request burst
31 ms / 30 ms / 29 ms).

## 4. Cutover sequence (Bundle X, when it is approved)

1. Point the Stage 2 gateway's upstream at the canary (`127.0.0.1:18080`) instead of the native
   backend (`198.51.100.110:8088`) by changing the policy bundle's routing, not the systemd unit.
2. Re-run the parity suite through the gateway path and compare bodies with the native listener.
3. Keep the native backend warm for the whole soak; the rollback is a policy edit plus a reload.
4. Only after the soak, retire the native vhost — and only if the client-IP problem is solved (below).

## 5. Monitoring thresholds (from the measured baseline, not invented)

| Signal | Baseline | Alert at | Why |
|---|---|---|---|
| Canary p50 (loopback, `/ai.html`) | 0.35 ms | > 2 ms | 5x the measured floor means the container is contending, not the network |
| Canary p95 | 0.55 ms | > 5 ms | separates a slow worker from a saturated one |
| Container memory | ~40 MB resident, cap 256 MiB | > 200 MiB | the cap is the failure boundary; hitting it kills the container, not the host |
| Restart count | 0 | > 0 in 1 h | a restart means the healthcheck or the config moved under us |
| Native p50 (regression guard) | 0.39 ms | > 5 ms | owner set 5 ms on 2026-11-16. The original 1 ms was 2.5x a baseline measured once, and the host now sits at exactly 1.0 ms - alerting on noise. 5 ms is still ~12x the measured floor and matches the canary's own p95 alert, so a real regression still pages |
| Log growth | ~1 KB/request | 2x normal | duplicate logging (container + host) is a known ingestion trap |

## 6. Abort conditions

- Any parity check fails with an **undocumented** difference (a difference not listed in
  `test_vhost_parity.sh`) — the canary is serving a different site than the native vhost.
- The container cannot be recreated from the recorded artifact (`test_rollback.sh` failure).
- Native p50 regresses beyond the threshold above while the canary is running.
- Preflight reports a stale compose artifact or a runtime version drift.

## 7. Rollback (tested)

`tests/container/test_rollback.sh` performs and asserts it: capture native response + docroot
snapshot + image id → `podman-compose down` → prove native :80 still serves the identical document
and the docroot is byte-identical → `podman-compose up -d` → prove the same image is running and
serving 200. Current run: 5 checks, 0 failures. For a Bundle X cutover the rollback is one step
shorter — repoint the gateway policy at the native backend and reload — because the container is
never the only listener until the soak completes.

## 8. Risk register

| # | Risk | Status | Evidence / mitigation |
|---|---|---|---|
| 1 | **Client identity is lost**: the container sees `10.89.0.1` (the podman bridge) as the client, so `RewriteMap` verdicts apply to the bridge, not the real source | **Open — the blocking issue for Bundle X** | Measured in `test_containment.sh` / `test_vhost_parity.sh`. Mitigations: host networking, a macvlan, or `mod_remoteip` with a trusted proxy header from the gateway. The gateway already sends `X-Forwarded-For` and `Forwarded`, so `mod_remoteip` in the image is the cheapest correct fix |
| 2 | **PHP is served as source** (`/centos7.php` 1914 bytes of source vs 1866 bytes rendered natively with `X-Powered-By: PHP/7.2.34`) | Open — decision proposed | Add a `php-fpm` service to the compose project and proxy `.php` via `proxy_fcgi`; alternatives and the recommendation are in `docs/container/canary-build-2026-11-14.md` |
| 3 | **SSO parity is impossible without mod_shib**: `/ldap/` and `/phpldapadmin/` return 302 (Shibboleth) natively and 403 in the canary | Open — accepted for the canary | Reproducing it means installing `mod_shib` and mounting the SP key, which widens the secret surface the image currently has none of |
| 4 | **Egress**: the container can reach `10.30.72.19:80` and `198.51.100.110:8088` — a compromised web process can talk to the host's published HTTP services | Accepted | Measured in `test_containment.sh`. Narrowing means an egress policy (firewalld/`nftables` for the podman network) or `network: slirp4netns` with port restrictions |
| 5 | **Banner fingerprint**: canary sends `Apache/2.4.37 (Oracle Linux Server)` while native sends `... OpenSSL/1.1.1k` | Accepted | Documented in the parity suite; the gateway is the TLS terminator in Profile C, so the image has no mod_ssl to produce the token |
| 6 | **`pids_limit` is not applied** by podman-compose 1.0.6 (2048 instead of 512) | Accepted | Documented; fix is a newer compose or a quadlet unit, which is a Bundle X decision |
| 7 | **Image is not reproducible**: the id changes on every build because the build context is copied to a fresh temp dir (mtimes move) | Open | Fix by building from a stable context or pinning mtimes; matters as soon as images are verified by digest |
| 8 | **Rollback could change host ownership** | Closed | `test_rollback.sh` compares the docroot snapshot (paths, owners, sizes) before and after the container lifecycle |
