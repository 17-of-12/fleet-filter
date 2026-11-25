# Development Handoff — Fleet-Filter Stage 3: Containerized Apache Containment

**Date:** November 14, 2026  
**Status:** Proposed architecture and implementation workstream; **not yet deployed**  
**Suggested repository destination:** `docs/CONTAINERIZED-APACHE-HANDOFF.md`  
**Relationship:** Stage 1 = scanner detection/quarantine/deception; Stage 2 = programmable pre-Apache security gateway; **Stage 3 = containment if Apache or an application is compromised**.

> **Owner decisions.** Docker is the initial implementation target. Existing developers must continue editing their existing host-side website trees, with no forced move to an image-build/deployment workflow. Apache runs in a container and consumes those trees through bind mounts. SELinux integration must be a project configuration **toggle**, set to **disabled for the current deployment**. Do not automatically change host SELinux mode or relabel existing web trees. Keep this stage independent of whether Stage 2 has shipped.

## 1. Mission and success criteria

Move the existing Apache *runtime*—HTTP daemon, loaded modules, PHP integration, configuration and supporting userspace dependencies—into a controlled container while preserving the existing website source directories and developer workflows on the host. Separate the replaceable runtime image from host-owned content and state.

The point is **containment**, not claiming that containers stop exploitation: if an Apache module, CGI script, PHP application, or other web process is compromised, reduce its access to host files, privileged processes, unrelated services, and network destinations. Containers share the host Linux kernel, so a kernel or runtime escape remains possible; this is defense-in-depth, not a VM-equivalent boundary.

**Must be true for a successful migration:**

1. Existing developer accounts, SSH/SFTP access, ACLs and deployment procedures still update the **same canonical host paths**, without `docker cp` or image rebuild for normal site edits.
2. A container sees updates to bind-mounted files; cache behavior (such as PHP OPcache) is documented and tested. Apache config/module changes still use a controlled image build or config reload.
3. Application behavior, hostnames, authentication, redirects, uploads, scheduled tasks and external integrations match the pre-migration baseline.
4. The site is not directly reachable around the intended gateway or existing protective frontend.
5. The container cannot normally modify source code; only narrowly enumerated application-state paths are writable.
6. Apache can be upgraded, replaced or rolled back independently of developer source trees.
7. A failure or rollback does not destroy, `chown -R`, relabel, overwrite, or relocate the website tree.
8. Security and operational claims are demonstrated through tests, not inferred from the presence of Docker.

## 2. Architecture and boundaries

```text
Internet clients
     |
     v
Stage 2 security gateway (when available)
  - public TLS / HTTP negotiation, inspection and policy
  - clean traffic -> approved backend
  - hostile traffic -> Stage 1 tarpit/deception
     |
     v
Container-restricted backend interface (not public)
     |
     v
+-----------------------------------------------------------+
| Stage 3: Apache runtime container                         |
| httpd + configured modules + app runtime as needed        |
| READ-ONLY: /var/www/html  <-- bind mount from host         |
| WRITABLE: only approved upload/cache/session/state paths  |
| restricted UID, capabilities, processes, network, memory   |
+-----------------------------------------------------------+
     ^                      |
     |                      v
Host developers:         Approved dependencies:
edit existing files      DB / LDAP / SSO / app services
through existing tools   only as required by that site
```

**Trust boundaries:** Internet -> gateway; gateway -> container; container -> developer-owned content; container -> specific writable application-state mounts; container -> configured service dependencies; container runtime -> host kernel. No ordinary application container may mount the Docker socket, the controller's SQLite DB, gateway keys, host root filesystem, or broad privileged host paths.

**Important sequencing:** Containerization must work even if Stage 2 is still being developed. A temporary, restricted existing frontend or native Apache proxy may be used for laboratory integration, but the container itself must not become an inadvertently public listener. Keep protocol selection independent: Stage 2 may send HTTP/1.1 or HTTP/2 to the backend, depending on tested policy; Stage 3 must not impose a permanent downgrade.

## 3. Existing environment — verify before acting

The **November 12 project archive** reports:

- `build01.lab`: Oracle Linux 9.8, native Apache 2.4, an existing `/var/www/html` DocumentRoot, several vhosts, and loaded modules including `ssl`, `http2`, `proxy`, `rewrite`, `remoteip`, and **`auth_mellon`**. SELinux was **Disabled** on this host when surveyed. Docker and Podman were present. The HTTP/2 workaround was pinned in the recorded Apache configuration.
- `lab-web01.lab`: Oracle Linux 8.10, native Apache, `/var/www/html` in the captured SSL vhost, and SELinux **Permissive**, not Disabled, when surveyed. The archive says Docker/Podman were not installed at that point.
- The owner has subsequently reported that the earlier controller/responder audit defects were fixed in commit `52307a2`. This handoff does not independently validate that new repository revision. Do not treat an older tarball as the current production state.

**These are historical observations, not deployment authorization.** Refresh the inventory from the current hosts before designing images or modifying services. The recent fleet-sweep workstream should supply current candidate hosts and versions.

## 4. Decisions already made, and decisions to investigate

| Topic | Decision / direction |
|---|---|
| Primary container runtime | **Docker Engine + Compose**, for the first prototype; Podman may be compared later, but do not stall the project on a runtime debate |
| Host web tree | Keep existing host path; bind-mount to the path expected by Apache inside the container |
| Web tree permissions | Prefer read-only from the container; host developers retain existing host-side write access |
| Apache image | Build a **site-compatible, versioned custom runtime image** with required modules; do not assume an off-the-shelf image is a drop-in for Oracle Linux's httpd packages |
| Container count | Start with one Apache container corresponding to a known host/site configuration unless isolation or dependency conflicts justify per-vhost separation |
| TLS | Stage 2 gateway ideally terminates public TLS; do not needlessly distribute keys into backend containers. Preserve a configurable exception for tested standalone use |
| Backend network | Private/restricted backend or localhost-only published port; verify real reachability including IPv6 and direct routing |
| SELinux project setting | **`security.selinux.enabled: false`**, default for this deployment; no mount relabel or host mode changes |
| Docker plugins | **Not needed** for ordinary web bind mounts or Apache module configuration; Docker's plugin system is not an HTTP inspection API |
| Migration | Per-host canary, measured acceptance gates, reversible cutover |
| Security baseline | No privileged container; no Docker socket; no broad host binds; limited capabilities; seccomp; least privilege; constrained egress |

## 5. Pre-migration discovery: do not assume `/var/www/html` is the entire application

For **each** candidate host, create an evidence-based inventory. Save the exact configuration and package versions as machine-readable artifacts and human-readable migration notes.

**Apache and protocol topology:** `httpd -V`, `httpd -M`, `httpd -S`, effective `Listen`/`Protocols`, MPM, vhost maps, `DocumentRoot`, `Alias`, `ScriptAlias`, `ProxyPass`, rewrite maps, `.htaccess` policy, `Directory` access rules, `mod_ssl`, `mod_http2`, authentication modules, headers, CGI, WebSockets, and client certificate requirements. Account for local include files, symlinks, and application server sockets.

**Application runtime:** PHP version, mod_php versus PHP-FPM, installed extensions and INI overrides, Python/Perl/CGI runtimes, Java integration, binary helpers, external programs spawned by applications, fonts/libraries, locales, timezone, service users, cron/systemd jobs, and any custom compiled Apache modules. A native EL8/EL9 `.so` file cannot simply be copied into an arbitrary official `httpd` image and assumed ABI-compatible.

**Filesystem:** Enumerate *all* vhost document roots, `Alias` targets, writable upload/cache/session directories, symlink destinations, nested filesystems, NFS/CIFS mounts, permission inheritance, ACLs, owner UID/GID, hard-coded absolute paths, log directories, temporary directories, secrets/config directories, and other host state accessed by the applications. Record `realpath`, `findmnt -R`, `stat`, and ACL samples for relevant trees.

**Identities and dependencies:** Map access to LDAP/AD/SSO (including `auth_mellon`, if used), client certs, keytabs, service tokens, databases, SMTP, DNS, file shares, local Unix sockets, and internal APIs. Determine whether rootless UID/GID mappings would change access to those resources.

**Operations:** Inventory log shipping, Wazuh integration, backup jobs, file ownership/ACL restoration, Apache reloads, external monitoring, patch cadence, service dependencies, firewall rules, and rollback procedures.

Do not assume the container must include the host's entire `/etc/httpd` or all of `/var/www`. Establish an explicit allowlist of required paths.

## 6. Filesystem model: unchanged developer workflow

Default host-side tree:

```text
HOST /var/www/html                -- developers continue editing here
  |  read-only bind
  v
CONTAINER /var/www/html           -- Apache reads the same content
```

If an Apache image uses a different default document root (e.g., `/usr/local/apache2/htdocs`), either configure its `DocumentRoot` deliberately or bind to its actual expected path. Prefer **matching the existing `/var/www/html` path in the customized container** to reduce application path breakage.

### Mount rules

1. Default to **read-only** source mounts. Set `read_only: true` explicitly.
2. Use Compose **long-form bind syntax with `create_host_path: false`** so misspelled/missing source paths fail rather than silently creating empty directories.
3. Never bind-mount the entire `/`, `/etc`, `/home`, or a developer's broad working directory as a convenience.
4. If an application needs uploads or cache persistence, use **separate narrow writable mounts** with unique owners and quotas. Prefer paths outside the web-executable area; if uploads must be served, explicitly prevent script execution there.
5. Do not recursively `chown` or `chmod` the existing developer tree to satisfy the container. Determine container UID/GID access and apply *targeted*, reviewable adjustments only where necessary.
6. Check symlinks: a symlink pointing outside a bind mount may break inside the container; do not fix it with an indiscriminate parent-directory mount.
7. Check nested mounts, network filesystems and legacy kernel behavior. Confirm they remain read-only and available in the container rather than trusting an option string alone.
8. Direct source edits should be visible without rebuilding the image, but application caches, PHP OPcache, and webserver configuration reload requirements must be tested separately.
9. Never put the authoritative database, credentials, or executable toolchain inside the document-root writable area.

### File ownership and the developer contract

Developers continue writing host files as before; the **container service identity** must be able to read required files without gaining developer write authority. Use a fixed unprivileged UID/GID for the process where compatible, and document mapping of UID/GID to the host. Supplemental groups, POSIX ACLs, rootless user namespaces, and NFS `root_squash` may require per-host accommodations. Preserve the host's established ownership and default ACL inheritance; avoid granting world-write privileges.

For content-management systems that self-update their PHP code, treat that as an explicit exception requiring a risk review: prefer deployment-driven updates; if runtime code writes are unavoidable, isolate those applications or vhosts and quantify the loss of containment.

## 7. Apache runtime image and patching

Build a minimal versioned runtime image containing Apache, required modules, configuration, required PHP integration (or a separately isolated PHP-FPM container), and only necessary libraries. Use an approved, actively patched base; pin base image digests for reproducibility and keep an update process that tracks the upstream vendor's security releases.

**Compatibility is a gate.** The image must satisfy existing `mod_auth_mellon`, `mod_ssl`, `mod_remoteip`, `mod_proxy`, `mod_http2`, rewrite, any custom modules, and each website's runtime requirements. Do not blindly swap the Oracle-provided Apache with `httpd:2.4` or `php:latest-apache` and assume feature parity, authentication compatibility, security patch equivalence, or the same filesystem layout.

Keep config and content separately managed: runtime/module changes via controlled image build; site content remains a bind mount. Avoid uncontrolled drift from hand-edited configuration inside a running container. Produce a manifest covering image digest, Apache version, module list, PHP/runtime versions, and SBOM. Use an approved registry or an auditable local image distribution process.

**Important CVE principle:** Moving a vulnerable Apache module into a container *does not patch it*; Stage 2 or a patch must still prevent exploitation. Stage 3 only attempts to contain the impact after a compromise.

## 8. Container hardening baseline

Use a *tested*, least-privilege baseline; do not apply incompatible flags blindly:

- **Non-root process** where practical; configure Apache to listen on an unprivileged internal port such as 8080 so no low-port bind capability is needed.
- Drop Linux capabilities by default; add exceptions only for demonstrated needs.
- `no-new-privileges` and Docker's default seccomp confinement; do not turn off seccomp to fix application errors without a documented review.
- Read-only root filesystem, with small explicitly writable `tmpfs` for PID/runtime/temp files. Make logging go to stdout/stderr or a specific controlled destination.
- Read-only source bind and narrowly writable application data mounts.
- Resource limits for memory, CPU, PIDs, file descriptors as supported, plus request-level limits in the gateway and Apache.
- No `--privileged`, host PID/IPC/network modes by default, Docker socket mounts, arbitrary devices, or broad secret mounts.
- Limit ingress to the gateway; assess egress policy **per application**, allowing only needed DB/LDAP/DNS/SMTP/dependency destinations. Docker bridge networking alone is not an outbound firewall.
- Consider rootless Docker or user-namespace remapping as a further containment control, but **validate file ownership and ACL behavior** before mandating it.
- Define a patch SLA for Apache, container base images, PHP and shared libraries; produce and retain signed/hashed build artifacts as available.

If disabling SELinux reduces defense-in-depth on a target host, be explicit about the remaining controls. Never describe containers as a security boundary equivalent to a separate VM.

## 9. Networking and interaction with Stage 2 / Stage 1

Preferred steady-state path: public `:443` -> Stage 2 gateway -> restricted Apache container endpoint. The tarpit remains a separate Stage 1 path; do not couple application runtime and deception container into the same writable storage.

Two backend patterns are acceptable:

**A. Host-side gateway to container:** Publish container Apache to `127.0.0.1:<dedicated-port>` and only connect from the local gateway. Verify Docker version and actual packet reachability. Docker documentation warns that releases **older than Engine 28.0.0** have allowed some localhost-published ports to be reached from the same L2 segment; test, firewall and/or use a more isolated network design accordingly. Do not rely on a loopback binding as an untested security guarantee.

**B. Gateway container to Apache container:** Put both services on an explicitly private Docker network, and do not publish the Apache backend port to the host. This can reduce backend exposure, but the gateway's own network and runtime permissions must remain isolated and reviewed.

Preserve original-client IP through **trusted gateway forwarding metadata** (`X-Forwarded-For` or `Forwarded` with correct `mod_remoteip` trust settings, or a negotiated PROXY protocol arrangement). Discard untrusted client-supplied forwarding claims. Confirm Wazuh/access logs still identify the right client and that the container cannot be called directly to bypass classification.

Do not enable host networking merely to preserve source IP. Do not assume Docker's default firewall modifications are identical to existing firewalld rules. Verify IPv4/IPv6, forwarding and Docker's installed version empirically.

## 10. SELinux configuration toggle — required, default OFF

This is **project deployment configuration**, not Docker Compose's native `security` property and **not a command to change host SELinux state**.

```yaml
# Example: containerization.yaml (project-owned configuration)
security:
  selinux:
    enabled: false     # DEFAULT FOR CURRENT DEPLOYMENT
```

**When `enabled: false` (current installation):**

- Do not add `:z`, `:Z`, `bind.selinux`, `chcon`, `restorecon`, `setsebool`, or automated relabel operations to generated deployment artifacts.
- Do not edit `/etc/selinux/config`, call `setenforce`, or attempt to disable/enable SELinux on the host.
- Detect and record `getenforce` when available. Disabled and Permissive host states do not enforce a label denial; if the host is **Enforcing** while project integration is disabled, fail preflight with a clear compatibility diagnostic rather than silently weakening enforcement.
- Continue enforcing all **non-SELinux** hardening: UID/GID, bind `read_only`, namespaces, seccomp, capabilities, resource limits, and network restrictions.

**When `enabled: true` (future capability):**

- Require a separately approved SELinux policy and per-host preflight; never infer that SELinux is enforcing merely because the toggle says `true`.
- Inventory existing contexts and roles of each mount source. Generate an explicit, narrow label strategy suitable for Docker or Podman on that specific host; do not recursively relabel a production `/var/www`, `/home`, or other large shared directory without a reversible plan and permission.
- Verify interactions with existing host Apache, developers, ACLs, network filesystems, and any shared mounts.
- Provide tested policy / relabel rollback and a compatibility report. A single `:Z` flag is **not** a general solution for a shared developer tree.
- An enabled option must be a separate tested feature, not merely an unimplemented switch that gives a false impression of confinement.

The **captured archive** reports `build01` as Disabled and `lab-web01` as Permissive. Do not generalize those measurements to the current fleet; verify independently.

## 11. Persistent state, secrets, logging and monitoring

- Separate **site code**, **site content/uploads**, **ephemeral cache**, **durable application data**, **TLS keys**, and **service credentials**. Classify each path as `ro-bind`, `rw-bind`, `managed-volume`, `tmpfs`, `secret`, or **not mounted**.
- Container images must not contain embedded production credentials or host secrets. Inject only needed secrets using controlled files/credentials with bounded exposure and a documented rotation procedure. Do not expose env files or tokens via logs or image layers.
- Place Wazuh-compatible structured logs on stdout/stderr or route via an approved logging driver/collector. Avoid container IDs as the only correlation key; record vhost, host, image version, request ID and actual client IP.
- Back up **host web trees and writable persistent data**, not ephemeral containers. Ensure backup and restore workflows understand file ownership and ACLs.
- Include health checks that actually test Apache request-serving, not merely process existence or configuration syntax. Expose no public admin endpoint; health routes must be private.
- Configure daemon/container restart behavior, startup ordering, dependency failures, log rotation, disk thresholds, image retention, and alerting.
- Maintain a documented update cycle for image builds and emergency CVE replacement. Scanner or tarpit policy updates must not unnecessarily rebuild web application images.

## 12. Migration strategy: no big-bang cutover

**Phase 0 — Current-state survey.** Refresh host/vhost/module inventory. Identify one low-risk site with representative dependencies; record source paths, writable paths, UID/GID/ACL, TLS/protocol expectations, current errors, headers, response behavior, and health metrics. Capture reversible configuration and backups.

**Phase 1 — Container image compatibility.** Build the minimal Apache/runtime image; reproduce module/vhost configuration in an isolated lab; validate `httpd -t`, module loading and the actual app dependencies. Keep existing native Apache untouched.

**Phase 2 — Live-content, nonpublic canary.** Mount the **same host web tree read-only** into the container, bind a distinct restricted backend port, and test using a laboratory hostname/Host header. Verify developer changes show up; do not alter live DNS or public listener ownership.

**Phase 3 — Security and functional parity.** Exercise virtual hosts, authentication, cookies, redirects, upload/download, PHP, WebSockets/SSE/gRPC if applicable, file ACL behavior, site writability restrictions, logging, monitoring, backend protocol negotiation, and direct-bypass attempts. Conduct a controlled simulated application compromise and verify containment without touching real production secrets.

**Phase 4 — Gateway integration.** Connect a canary gateway route to the container. Confirm the same request signatures, tarpit classifications, original-client attribution, and protected-backend restrictions. If Stage 2 is not ready, use a restricted nonproduction route and proceed with Stage 3's independent testing.

**Phase 5 — Approved cutover.** Freeze runtime configuration (not developer content unless necessary), produce a validated rollback checkpoint, switch only the selected vhost or traffic slice, monitor baseline latency/errors/authentication and resource usage, and maintain immediate reversal capability. Do not disable the native service until the new route is proven, and do not create competing listeners on `:80`/`:443`.

**Phase 6 — Replication.** Convert additional compatible sites in small batches. Split runtimes by vhost where dependencies or trust boundaries justify it. Do not declare fleet completion from one easy static site.

### Rollback invariants

- Container cutover never changes ownership or contents of the host web tree as an incidental operation.
- Rollback may restore the last approved **serving path** but must not reopen a known vulnerable Apache protocol directly to the internet. Retain a compensating Stage 2 policy or approved emergency mitigation.
- Config/image revisions, original Apache service unit state, firewall state, and gateway backend selection are versioned or backed up.
- Reversal is testable and does not require restoring a developer tree from backup merely to restart the original service.

## 13. Test and acceptance matrix

| Area | Required proof |
|---|---|
| Live source | Editing a known file through the normal developer account changes the website response; no image rebuild, copying or host ownership change |
| Read-only | Container cannot modify or delete host source; host developer still can |
| Writable state | Uploads/sessions/cache work only in narrow intended mounts; executable code cannot be written into a script-enabled directory without explicit exception |
| Virtual hosts | All target vhosts, paths, aliases, rewrites and redirects pass parity tests |
| Authentication | Existing SSO/LDAP/AD/Mellon or other auth flows pass; no secrets leak into image or logs |
| Backend security | Unauthorized direct container access and bypass from non-gateway networks are rejected; verify IPv4 and IPv6 |
| Containers | No privileged mode, Docker socket, broad host mounts, or unnecessary capabilities; resource limits verified |
| Networking | Legitimate backend dependencies work; disallowed egress fails according to documented policy |
| SELinux OFF | Generated configuration contains no SELinux label or relabel operations; host configuration remains untouched |
| SELinux ON (future) | Independently validated enforcing-host policy, mount labels and reversible file-label actions; not a first deployment gate |
| Runtime updates | Security-patched image rebuild, compatibility test and rollback demonstrated without touching source content |
| Logging | Wazuh/monitoring see original client attribution and correlate gateway-to-Apache requests |
| Availability | Container restart and backend failure are detected; healthy routing resumes; no production fallthrough for quarantined sources |
| Performance | Compare native Apache and containerized Apache on identical representative traffic, HTTP protocol choices, CPU/memory and tail latency |
| Recovery | Rollback returns the approved site to service without ownership, ACL, mount or content changes |

Define acceptance thresholds from actual host baselines and existing application SLOs before production cutover. Record raw measurements and test commands.

## 14. Illustrative Compose scaffold — lab only

This **assumes a custom image** has been built with Apache configured to run non-root on port `8080`, writes PID/temp state under `/run/httpd` and `/tmp`, and logs to stdout/stderr. It is **not directly deployable** against an arbitrary upstream `httpd` or `php:*-apache` image without that image work.

```yaml
# compose.yaml — narrow example for a Stage 3 canary
services:
  apache:
    image: fleet-filter/apache-canary:lab   # local image built by Phase 1
    restart: unless-stopped
    user: "10080:10080"                      # verify access to host ACLs
    read_only: true                          # container root filesystem
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    pids_limit: 256
    mem_limit: 512m                           # tune after measurement
    tmpfs:
      - /tmp:rw,nosuid,noexec,size=64m
      - /run/httpd:rw,nosuid,size=16m
    ports:
      - "127.0.0.1:18080:8080"              # lab; verify no network bypass
    volumes:
      - type: bind
        source: ${WEBROOT:?Set WEBROOT to the existing host web directory}
        target: /var/www/html
        read_only: true
        bind:
          create_host_path: false
    # Add separate narrow rw mounts ONLY for audited application state.
    # SELinux is OFF: no :z/:Z, relabel or label=disable directives.
```

**Validation before using the scaffold:** confirm image configuration, rootless/namespace behavior, actual bind target, nested mount permissions, health endpoint, bridge firewall exposure, and test behavior with existing developer ACLs. The `security.selinux.enabled: false` setting belongs to **the project's deployment generator or policy configuration**, not as an invented Compose key.

## 15. Required development-agent deliverables

**A. Containerization design assessment.** Map the existing Stage 1/2/3 integration, trust boundaries and operational assumptions; explain what containment does and does not protect.

**B. Current fleet and site inventory.** Provide source evidence, host OS/Apache/module inventory, vhost and mount manifests, runtime and auth dependencies, and risk ranking. Cross-reference the existing Bundle K fleet sweep.

**C. Runtime decision record.** Select Docker configuration and image provenance for the first target, document the Podman/rootless tradeoffs without making them prerequisites, and establish an image patching/rollback policy.

**D. Mount and identity plan.** For each site list source, target, read/write mode, UID/GID, ACL expectation, persistence class, symlink handling and exposure risks. Prove developers retain the same paths.

**E. SELinux option implementation.** Implement the project-owned `security.selinux.enabled` toggle, set **false**, verify no host-mode changes and no relabeling. Document how an independently tested enforcing-host profile can be added later; do not silently simulate SELinux enforcement.

**F. Hardened PoC image and Compose configuration.** Implement the nonpublic canary, reproducible build instructions, pinned runtime dependencies, and checked configuration. Do not create a publicly accessible Apache listener.

**G. Automated tests and operational scripts.** Include preflight, parity tests, security assertions, observability, backup/recovery, upgrade and rollback. Prefer idempotent scripts, explicit logs and failure traps.

**H. Migration runbook and risk register.** Provide per-site prerequisites, planned cutover, DNS/port/gateway sequence, monitoring thresholds, abort conditions, and tested rollback.

**I. Validation report.** Separate demonstrated behavior from assumptions; provide concrete evidence of filesystem preservation, containment, availability, and parity.

## 16. Non-goals and guardrails

Do **not** rewrite sites into a container-native development workflow; mandate CI/CD just to change a web page; require developers to SSH into a container; relabel or recursively change ownership of existing host web trees; move arbitrary Apache configuration and host secrets wholesale into the image; require Stage 2 to be complete before the Stage 3 lab; expose backend ports directly; install Docker plugins to solve HTTP inspection; turn SELinux on/off on the host; or treat Docker as proof that exploitation is harmless.

Do **not** silently remove specialized Apache modules, authentication mechanisms, PHP features, CGI utilities, shared filesystem mounts, or backend protocol capabilities because they complicate an example image. Record incompatibilities and resolve them explicitly before cutover.

## 17. Immediate next instructions to the local development agent

1. Archive this document at `docs/CONTAINERIZED-APACHE-HANDOFF.md` and open a separate **Stage 3 containerization** work bundle in the existing `TODO.md` tracking structure. Keep Stage 2 gateway work independent.
2. Refresh the target fleet and select a safe nonproduction canary. Verify current SELinux mode but **use project toggle `enabled: false`**. Do not install a runtime or change listeners on production hosts without an approved plan.
3. Produce the vhost/module/filesystem/identity dependency matrix, paying particular attention to `auth_mellon`, PHP, symlinks, and writable application state.
4. Build a site-compatible Apache image and demonstrate a nonpublic container serving from the **unchanged host web tree** using an explicitly read-only bind mount.
5. Prove developer edit visibility, production-code write denial inside the container, correct virtual-host behavior, private backend reachability, and rollback before considering production cutover.
6. Document any blockers, especially special modules, SSO integrations, rootless UID mappings, mounted shares, app write requirements, and Docker firewall behavior. Resolve based on evidence, not speculative workarounds.

**Final design principle:** Developers continue to own and modify the same host-side code trees. We replace and confine the webserver runtime around those trees. Stage 2 tries to prevent exploitation before Apache receives the request; Stage 3 aims to constrain damage when prevention fails. Neither layer should compromise the site's functionality or unexpectedly modify the developer filesystem.

---

## Reference documentation (for implementation verification)

- Docker bind mounts: https://docs.docker.com/engine/storage/bind-mounts/
- Docker Compose service volumes and `create_host_path`: https://docs.docker.com/reference/compose-file/services/
- Docker port publishing caveats: https://docs.docker.com/engine/network/port-publishing/
- Docker rootless mode: https://docs.docker.com/engine/security/rootless/
- Docker default seccomp: https://docs.docker.com/engine/security/seccomp/
- Apache upstream versus distribution layout: https://cwiki.apache.org/confluence/spaces/HTTPD/pages/115522293/DistrosDefaultLayout
- Podman run and SELinux bind options (future-only): https://docs.podman.io/en/latest/markdown/podman-run.1.html

**Project-specific historical source:** Uploaded `Fleet-Filter-20261114T120542Z.tar` (`docs/HANDOFF.md`, `SKILL.md`, `data/research/phase0-host-survey-2026-11-12.md`, and Apache config captures). Newer host facts and later commits must be revalidated on the current repository and fleet.
