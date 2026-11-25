# Stage 3 container runtime decision record — first target `lab-web01.lab` (Bundle U1, U7)

Status: **accepted for the canary, 2026-11-14**. Evidence for every host fact cited here is in
`data/results/container-target-discovery-2026-11-14.md`. Owner review of the Stage 3 *cutover*
(Bundle X) is still required; this record only settles the runtime and the mount surface for the
canary, which is what U1 asks for.

## Decision

| Question | Answer |
|---|---|
| Runtime on the canary | **Podman 4.9.4** (`podman-4:4.9.4-38.0.1.module+el8.10.0+91087+698d4460`, `container-tools:ol8` from `ol8_appstream`) |
| Runtime on the fleet generally | Docker CE where it is already installed and working (`build01.lab`: Docker CE 29.9.3 + containerd 2.4.2 + runc 1.5.3, plus Podman 5.8.2 rootless alongside it); Podman from the vendor module on EL8 hosts that do not already have Docker |
| Compose | Compose v2 syntax, executed as `docker compose` on Docker hosts and as `podman-compose` (or `docker compose` against `podman.socket`) on Podman hosts. Neither tool is installed on either host today — measured — so Compose is an explicit install, not an assumption |
| Rootless | Documented, **not used** for the canary (see tradeoffs) |
| Image for the first target | An **EL8-derived httpd image built from the repo's own Containerfile** (`oraclelinux:8` + the distro `httpd` RPM), not an upstream Debian `httpd:2.4` |
| SELinux | Inherited as found: `permissive` on lab-web01. Not changed by this decision |

## Why this deviates from the brief, and why that is not a contradiction

The Stage 3 brief states "Docker Engine + Compose is the owner's chosen runtime". On the chosen
canary that runtime is not installable from any enabled repository: lab-web01's enabled repos are
`ol8_baseos_latest`, `ol8_appstream`, `ol8_UEKR7`, `ol8_developer_EPEL(+modular)`, `remi-safe`,
`remi-modular`, `duosecurity`, `shibboleth`, `wazuh` — no Docker CE repo, and `docker`, `containerd`,
`runc`, `crun` are all absent on the host. The vendor-provided container runtime on EL8 is the
`container-tools` module.

Three options were weighed:

1. **Enable the Docker CE repository on lab-web01.** Matches the brief literally. Cost: adds a
   third-party repo (and `containerd.io`, which conflicts with the podman-provided container stack
   pattern on EL8) to a host that also runs Shibboleth, Wazuh, fail2ban, Duo and Remi PHP — and it
   creates a second, different Docker install to maintain next to build01's 29.9.3. The Docker skill
   for this fleet explicitly warns that RHEL-8-family distributions have Podman as the native default
   and that existing runtimes must never be removed blindly when other workloads depend on them.
2. **Podman from `ol8_appstream` (chosen).** Vendor-supported, module-pinned, no third-party repo,
   and it is the same runtime family already present on build01, so the canary does not teach us
   something build01 cannot reproduce. Cost: Compose must come from `podman-compose` or the Podman
   Docker-compatible socket rather than the Docker Compose v2 plugin, and any Docker-specific feature
   (Swarm, `docker compose` plugin behaviour) is off the table on this host.
3. **Build the canary on build01 instead, where Docker CE already runs.** Rejected by owner direction
   ("use toolbox for testing") and on merit: build01 is the Ansible control node and the Stage 2
   gateway build host, so putting the first containerised web runtime there would test Stage 3 on the
   control plane.

Recording the deviation matters more than picking the theoretically correct side: if the owner wants
Docker CE on EL8 after all, the change is one repository enablement plus a rebuild of the canary, and
everything else in this record (image provenance, mount allowlist, rollback policy) is unchanged.

## Image provenance for the first target

- **Base**: `oraclelinux:8` pinned by digest, then install the distro `httpd` RPM — the same
  `Apache/2.4.37 (Oracle Linux Server)` build the host runs today. This is the only option that
  preserves `mod_shib_24.so` (built against APR 1.6.3 / OpenSSL 1.1.1k / the Oracle httpd build) and
  the Remi PHP 7.2 extension set; an upstream Debian `httpd:2.4` image would require rebuilding
  Shibboleth and every PHP extension against a different Apache and OpenSSL, which is a project of
  its own, not a mount.
- **Build location**: a `Containerfile` under `container/` in this repo, built by a
  `bin/build-container-apache.sh` sibling to `bin/build-gateway.sh`, so the image is reproducible from
  source the same way the Stage 2 gateway binary is.
- **Provenance record**: each build writes `data/artifacts/fleet-filter-apache-<version>-<gitsha>.json`
  with the base digest, the httpd RPM version, the module list captured with `httpd -t -D DUMP_MODULES`,
  and the produced image digest — mirroring `data/artifacts/fleet-filter-gateway-*.json`.
- **Config source**: the container's `/etc/httpd` comes from the image plus a bind-mounted config tree
  from this repo's `apache/` directory, never from an in-container edit. That requires the deployed
  config to exist in the repo first, and it now does: `apache/lab-web01.httpd.conf` was added after
  this audit found that the modified `/etc/httpd/conf/httpd.conf` (RPM-owned; `rpm -V httpd` reports
  `S.5..UGT.`) had never been captured. `apache/lab-web01.ssl.conf` was already byte-identical to the
  deployed `ssl.conf`, and `shib.conf` is `shibboleth-3.6.0-1.el8` package content that the image
  receives from the same RPM rather than from a mount.

## Image patching and rollback policy

- **Pinning**: base image by digest, never by tag alone. The produced image is tagged
  `fleet-filter-apache:<version>-<gitsha>` and its digest recorded in the artifact JSON.
- **Rebuild triggers**: (a) a base-image or `httpd` RPM erratum for EL8; (b) a change to the repo's
  `apache/` config tree; (c) the CVE-2026-119618 staging mitigation changing (the image bakes
  `Protocols http/1.1` into the vhost exactly as Bundle K1 did on build01, so the mitigation travels
  with the image instead of being applied per host).
- **Cadence**: rebuild on errata, plus a scheduled monthly rebuild so a stale base cannot accumulate
  silently — the same reasoning as the gateway's rebuild policy in ADR-0001.
- **Rollback**: keep the previous image tag on the host; rollback is *recreate the container from the
  previous tag*, never mutate a running container. Config rollback follows the gateway's
  keep-last-known-good pattern: a new config tree is validated (`httpd -t`) before it is swapped, and a
  failed validation leaves the running container on the old tree.
- **Never**: `docker cp` into a running container as a way to ship a site change. The site content is a
  bind mount; the image is rebuilt.

## Rootless: documented, not a prerequisite

The brief lists Podman and rootless tradeoffs as documented-but-not-required. Measured against this
target, rootless costs more than it buys:

- **Privileged ports**: rootless cannot bind :80/:443 without
  `net.ipv4.ip_unprivileged_port_start=0`; the canary serves on `198.51.100.110:8088` and `:80`/`:443`.
- **UID mapping vs the file contract**: the docroot is `root:root 755`, Apache runs as `apache`, the
  php-fpm socket ACL names `apache,nginx` explicitly, and the Shibboleth SP key is `0600 shibd:shibd`.
  Rootless maps container root to an unprivileged host uid, so every one of those ownership and ACL
  checks changes meaning — the exact class of failure already hit twice on this project (the gateway
  user that could not read a group-readable TLS key, and the backend address that quarantined itself).
- **SELinux**: on a `permissive` host, rootless containers still relabel or require `:z`/`:Z` on every
  bind mount; the failure mode is silent until a file reads empty.

Decision: run the canary container **rootful**, with an explicit `--user` and explicit mount
annotations, and revisit rootless only when a second target forces the question.

## U7 — explicit mount allowlist and risk ranking

The container may mount **only** these paths (anything else is a policy change, not an ops detail):

| Mount | Mode | Reason |
|---|---|---|
| `/var/www/html` | `ro` | the developer-edited tree (Stage 3's whole point) |
| `/var/www/cgi-bin` | `ro` | `ScriptAlias` target |
| `/usr/share/httpd/icons`, `/usr/share/httpd/noindex` | `ro` | default `Alias` targets |
| `/usr/share/phpldapadmin/htdocs` | `ro` | `/phpldapadmin`, `/ldapadmin`, `/ldap` aliases |
| `/usr/share/shibboleth` | `ro` | serves the SP stylesheet |
| `/etc/httpd` (repo-provided tree) | `ro` | config from source control, not from in-container edits |
| `/etc/shibboleth` | `ro` | SP metadata + key; needs an explicit read strategy for the `0600` key |
| `/etc/ssl/certs/lab-web01.crt` | `ro` | certificate |
| `/etc/ssl/private/lab-web01.key` | `ro` | key; tighten to `0600` and set the container user before first deploy (it is group-readable today) |
| `/var/log/httpd` | `rw` | access/error logs, still readable by host `filebeat` and the Wazuh agent |
| `/var/lib/php/session` | `rw` | PHP session state |
| `/run/php-fpm/www.sock` | `rw` | only if PHP-FPM stays on the host while Apache moves into the container |

Explicitly **not** mounted: `/` , `/home`, `/root`, `/tmp` (the container gets its own tmpfs), any
autofs-managed path from `/etc/auto.files*`, and any host path under `/var/lib/docker` or
`/var/lib/containers`.

### Risk ranking

| # | Risk | Why it matters | Mitigation |
|---|---|---|---|
| 1 | **Client IP is lost across the container network** | Stage 1 (`SetEnvIf Remote_Addr`, `RewriteMap`) and Stage 2 (`X-Forwarded-For`, `X-Tarpit-Client`) both key on the address Apache sees. A bridge network rewrites the gateway's source address, so enforcement would key on the wrong IP — the same failure already measured when the gateway's hop was sourced from `198.51.100.110` | Use host networking or `macvlan`/`pasta` for the canary, and make "client IP correct behind the gateway" a named Bundle W test rather than an assumption |
| 2 | **`mod_shib` ABI** | The SP module cannot be loaded into a non-EL8 Apache image; losing SAML on a site whose `/shib` app depends on it is a functional regression | EL8-derived image (this decision); verify `httpd -t` loads `mod_shib` in the image before cutover |
| 3 | **Config drift owned by a user account** | `000-default.conf.disabled`, `shib.conf` and `ssl.conf` are `webadmin:users`, and two of them are RPM-owned files that were chowned, so an `rpm` update rewrites them as `root:root` and the deployed state diverges from both the package and the repo | Resolved for content: `ssl.conf` is byte-identical to `apache/lab-web01.ssl.conf`, `shib.conf` is package content, and the previously uncaptured `/etc/httpd/conf/httpd.conf` is now `apache/lab-web01.httpd.conf`. Open question: whether the user ownership was deliberate |
| 4 | **Log ingestion breaks** | `/var/log/httpd` is `0700 root:root` and is read by `filebeat` and the Wazuh agent; a container writing as a different uid can change that | Mount `rw` with explicit uid/gid and verify both shippers still read the files in Bundle W |
| 5 | **overlayfs on btrfs** | `/var` is a btrfs subvolume, so container storage on `/var/lib/...` runs overlayfs-on-btrfs (copy-up cost, documented EL8 behaviour) | Measure in Bundle W; if unacceptable, use the `vfs` storage driver for the canary or place container storage on a non-btrfs mount |
| 6 | **PHP delivery path is ambiguous on the host** | `php.conf` configures both the mod_php handler and a `proxy:unix:/run/php-fpm/www.sock` handler, and `php-fpm` is disabled at boot while its socket exists | Decide explicitly: PHP-FPM on the host (socket mounted into the container) or PHP-FPM inside the image; do not ship both handlers |
| 7 | **suEXEC contract** | `suexec` is compiled with `AP_DOC_ROOT="/var/www"` and `AP_UID_MIN=1000`; CGI execution inside a container with different users can fail in ways the host never did | Keep `cgid`/`suexec` disabled in the canary until a CGI site actually needs it |
| 8 | **Two runtimes across the fleet** | Docker CE on build01, Podman on lab-web01 means two toolchains to operate and two sets of quirks in runbooks | State the per-host-class rule in this record; revisit when the fleet-wide rollout is approved |

### Blocker list (must clear before Bundle V builds the canary image)

1. ~~Diff and upstream the three `webadmin:users`-owned `conf.d` files~~ - done 2026-11-14: `ssl.conf`
   matched the repo byte for byte, `shib.conf` is package content, and the file actually missing was
   `/etc/httpd/conf/httpd.conf`, now captured as `apache/lab-web01.httpd.conf`.
2. Decide the PHP delivery path (risk 6) — it determines whether the image needs PHP at all.
3. Settle the client-IP topology (risk 1) in writing before any container is started, because it
   changes the Stage 1 vhost rules the gateway already depends on.
4. Confirm the owner accepts **Podman** on EL8 for the canary, or authorise enabling the Docker CE
   repository on lab-web01 (the deviation above).
