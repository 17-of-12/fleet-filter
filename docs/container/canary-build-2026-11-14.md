# Stage 3b canary build and verification — lab-web01 (Bundle V), 2026-11-14

Image: `localhost/fleet-filter-apache:0.1.0` / `:0.1.0-5954f1c` (current image id `36f5ec96909b54b5ddd9e8fd15e754843ac47e32179ce3c2e5674c1e072dd800`),
built on lab-web01 from `container/Containerfile` against
`docker.io/library/oraclelinux@sha256:9225108d00fb6611ebc4a5eced166f27d9dcfeaa539fb127be79425f0da5e745`.
Staging tree on the target: `/opt/fleet-filter-container/` (`Containerfile`, `canary/`, `config.yaml`,
`compose.yaml`, `preflight.sh`, `bin/`). Container: `fleet-filter-apache-lab-web01`, published
`127.0.0.1:18080 -> 8080`.

## What was built

| Artifact | Purpose |
|---|---|
| `container/config.yaml` | the project-owned configuration: target, runtime pin, image pin, publish address, security block, complete mount surface |
| `bin/render-container-compose.py` | renders `container/compose.yaml` from the config and stamps the config hash into the artifact header |
| `container/compose.yaml` | the generated Compose v2 artifact (long-form binds, `create_host_path: false`) |
| `container/preflight.sh` | V3 preflight: SELinux-vs-toggle, host identity, runtime version, mount sources, port, artifact freshness |
| `container/Containerfile` | the image recipe (EL8 base by digest, distro `httpd`, baked canary config, `USER 980:980`) |
| `container/canary/httpd.conf`, `container/canary/conf.d/fleet-filter-canary.conf` | the configuration the image carries, including the Stage 1 `RewriteMap` rules |
| `bin/build-container-apache.sh` | build, `httpd -t` validation inside the image, provenance record |

## V-by-V result

- **V1 (image)** — complete. Built and tagged `0.1.0-5954f1c`; base pinned by digest; `httpd -t`
  inside the image returns `Syntax OK`; the provenance record is
  `data/artifacts/fleet-filter-apache-0.1.0-5954f1c.json` and now carries the SBOM half too:
  **206 packages** captured from the image's own rpmdb, sha256 recorded, including
  `httpd-2.4.37-65.0.1.module+el8.10.0+91092+d4ec9ae3.8` and `mod_http2-1.15.7-10.module+el8.10.0+91023+3994037c.7` -
  the same versions the native host runs, so the canary is not silently testing a newer Apache than
  the one it would replace. Building the SBOM into the script surfaced one more defect: the first
  attempt used an rpm `--qf` JSON template, which came out empty because the template cannot survive
  the shell quoting, and `2>/dev/null` hid the rpm error. The script now captures plain `rpm -qa`
  output, parses NEVRA in python, and refuses to record an empty SBOM.
- **V2 (SELinux toggle)** — implemented as a real config key (`security.selinux.enabled: false`)
  consumed by the renderer, not as an invented Compose key. With the toggle off the renderer emits no
  `:z`/`:Z` suffix and no SELinux key; the preflight greps the artifact for `:z`, `:Z`, `chcon`,
  `restorecon`, `setsebool` and fails if any appear. Host SELinux state on the target is untouched
  (`Permissive` before and after the run; the preflight prints `host-selinux-before` for the record).
- **V3 (preflight must fail on Enforcing + toggle false)** — complete, and no longer waiting on an
  Enforcing host. `tests/container/test_preflight.sh` runs the preflight against a `getenforce` shim
  and a generated config, and asserts all four SELinux branches (false+Enforcing fails with the
  documented diagnostic, false+Permissive passes, false+Disabled passes, true+Permissive fails as
  "configured and does nothing"), plus artifact staleness and the wrong-host refusal. 7 checks, 0
  failures, run on build01. The test also caught a bug in itself worth recording: the repo root was
  resolved as `tests/container/..`, and the first staleness probe drifted the config with a *comment*
  edit, which the parsed-config hash correctly ignores - drift has to be structural.
- **V4 (nonpublic canary)** — published on `127.0.0.1:18080` only, with the unchanged host tree
  bind-mounted read-only in long form (`create_host_path: false`). Verified: `GET /ai.html` through
  the container returns md5 `d6cac5d53a4619de28a463469880368b`, identical to
  `/var/www/html/ai.html` on the host, so the container is serving the host's tree, not a copy.
- **V5 (hardening baseline)** — verified from `podman inspect`: `user=980:980`,
  `readonly=true`, `cap_drop=[...]` (the full dropped set), `security_opt=[no-new-privileges]`,
  `mem=268435456` (256 MiB), `cpus=1.0`, `restart=unless-stopped`, no `--privileged`, no runtime
  socket mount, private PID/IPC/network namespaces (`net=fleet-filter-lab-web01_default`).
  **Deviation:** `pids_limit: 512` was not applied — podman-compose 1.0.6 created the container with
  `pids=2048` (the runtime default). The limit is in the generated artifact and in the image's
  Compose source, but this compose version does not honour it; either pin a newer podman-compose or
  accept the runtime default and say so.
- **V6 (reachability / non-reachability)** — `127.0.0.1:18080` answers (403 for `/`, 200 for
  `/ai.html`, 200 for `/centos7.php`, 0.4–1.2 ms). `10.30.72.19:18080` from the host and from
  build01 both refuse the connection, which is the correct non-reachability result for a
  loopback-only publish. **IPv6 is out of scope by owner decision (2026-11-14)**, so the IPv4-only
  publish satisfies V6; lab-web01 has no global IPv6 address either, and the same scoping already
  applies to P6 on the Stage 2 backend.

## Defects found and fixed during the build (each one was a real failure, not a draft cleanup)

1. **`from __future__ import annotations` broke the renderer on the target.** EL8 ships Python 3.6.8,
   where that import is a hard `SyntaxError`; the target-side preflight failed with it. The renderer
   is now 3.6-compatible, and the project rule it exposes is that anything a target executes must
   target 3.6, while anything the *control node* renders may target the venv's 3.12.
2. **PyYAML 3.12 on the target cannot render, only verify.** `safe_dump(sort_keys=...)` needs PyYAML
   >= 5.1. The preflight therefore compares the artifact's recorded config hash against the config on
   disk instead of re-rendering, so an old target PyYAML can never produce a false "stale" verdict.
3. **`User 1001` is not a valid Apache user directive.** Apache resolves names, and a bare numeric
   uid needs a leading backslash; the first image build died with `AH00543: httpd: bad user name 1001`
   even though uid 1001 existed in the image. Fixed by naming the account (`fleet-filter-apache`).
4. **Identity collisions on a shared host, twice.** uid 1001 on lab-web01 is the login account
   `druser`, so a container running as 1001 makes its files look like another person's. The first fix
   moved to uid 983, which has no passwd entry but *is* the primary **group** of the `wazuh` account
   (gid 983), so files created by the container came back on the host as `983:wazuh`. The rule that
   came out of it: an id has to be free in **both** the passwd and the group database before the
   project claims it. The container now runs as `980:980`, free in both, adjacent to the Stage 2
   gateway account (`fleet-filter-gw`, uid 984).
5. **The host's `/var/log/httpd` is `0700 root:root`,** so a non-root container cannot write it and
   httpd dies with `AH00091: could not open error log file`. The canary now logs to
   `/var/log/fleet-filter-canary` (owned 980:980) mounted at the container's `/var/log/httpd`, which
   also keeps canary logs separable from native Apache logs for filebeat. This corrects the U7
   allowlist entry that named `/var/log/httpd` as the mount.
6. **`CustomLog ... combined` without a `LogFormat` is a literal string,** not a nickname: the first
   runs logged the word `combined` on every line. The canary main config now defines `common`,
   `combined`, and a `correlated` format matching the field set the native gateway-backend vhost logs.
7. **`HEALTHCHECK` is ignored for OCI-format images** built by podman 4.9.4 (`HEALTHCHECK is not
   supported for OCI image format and will be ignored. Must use docker format`). The healthcheck is in
   the Containerfile but inert unless the image is built with `--format docker`.
8. **PHP is served as source by the canary.** `/centos7.php` returns the file's bytes (md5 matches the
   host file) because the image installs `httpd` only. This is the decision-record's open question 6
   made concrete: until the PHP delivery path is decided, a containerised Apache either leaks PHP
   source or has to carry its own PHP - the same class of defect as PT-03 on the native responder.
9. **`/var/lib/php/session` is `root:apache 0770` on the host,** so the container user could not
   write the session mount the configuration declared writable. Found by
   `tests/container/test_containment.sh` rather than by review. The canary now mounts its own
   `/var/lib/fleet-filter-canary/session` and leaves php-fpm's directory alone, which is also the
   right shape if PHP delivery later moves into the compose project.
10. **`bin/build-container-apache.sh` was committed 0644,** so every deploy needed a manual
    `chmod +x` on the target after the copy; all five container scripts are 755 in the repo now.
11. **The client IP is the podman bridge address.** The canary's access log records
   `10.89.0.1` for a request that arrived on the host loopback, so the Stage 1 `RewriteMap` - which
   keys on `REMOTE_ADDR` - would key on the bridge, not the client. This is risk 1 from the decision
   record, now measured rather than predicted, and it is the reason Bundle X cannot be a simple
   cutover: the container needs host networking, a `macvlan`, or `mod_remoteip` with a trusted proxy
   header before it can enforce the same verdicts as a native vhost.

## Decisions taken while closing the bundle

**`pids_limit` (V5): accepted at the runtime default, not a config error.** podman-compose 1.0.6 does
not translate `pids_limit`, so the container runs with podman's default 2048 rather than the
configured 512. Two ways out exist - pin a newer podman-compose, or move the canary to a systemd
quadlet unit, which does honour the limit and would also give the container the same
systemd-managed lifecycle the Stage 2 gateway service has. Neither is done now because the limit is
not the constraint that would be hit first (the memory cap is enforced correctly at 256 MiB), and
choosing the compose implementation is Bundle X's decision to make alongside the gateway cutover. The
value stays in the generated artifact so the intent is not lost.

**PHP delivery: proposed, awaiting the owner.** The image installs `httpd` only, so `.php` is served
as source - the same defect class as PT-03 on the native responder. Options:

1. **Add a `php-fpm` service to the same compose project** and point the canary vhost's `.php`
   handling at it through `proxy_fcgi` (the vhost already loads `proxy_fcgi_module`). Keeps the
   Apache container's docroot read-only, matches the host's own delivery model (Apache + php-fpm over
   a socket), and keeps PHP's own file writes inside the fpm container. **Recommended.**
2. **Install PHP into the Apache image** (`httpd` + `php` + `php-fpm` in one container). Fewer moving
   parts, but it couples the web server's image to the application runtime and rebuilds Apache
   whenever PHP changes.
3. **Mount the host's `/run/php-fpm/www.sock` into the container.** Cheapest, but it makes the
   container depend on host state the project does not own and defeats the point of an isolated
   runtime; it also requires the socket mount the config currently declares disabled.

Recommendation 1, because it is the only option that keeps the read-only docroot story intact. It
needs the owner's approval before the image surface grows, and it is the reason the canary is
described as *static* until then.

## Still open

1. Owner approval of the PHP delivery option above (or a decision to keep the canary static).
2. The compose implementation question (podman-compose 1.0.6 vs quadlet), which belongs to Bundle X.
3. Reproducible builds: the image id changes on every build because the build context is copied into
   a fresh temp directory, so mtimes move (`7a4ee5fe4b84` → `9534ac3d21f4` for identical content).
   Fixing this means building from a stable context or pinning mtimes, and it matters as soon as
   anyone wants to verify an image by digest rather than trust a build log.
