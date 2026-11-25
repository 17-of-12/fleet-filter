#!/usr/bin/env python3
"""Collect container runtime state from fleet hosts into one JSON inventory (Bundle AA).

Why this exists
---------------
The fleet console knew which *Fleet Filter* artifacts were deployed, but nothing about the container
runtimes actually running on those hosts. That gap is not cosmetic: on lab-web01 the running Apache
container is started from `localhost/fleet-filter-apache:0.1.0`, a tag that currently points at the
`0.1.0-eb7555c` build, while five older tags for the same image are still on disk. Nothing in the
console could answer "is this host running the version we shipped, and is it restarting?"

Scope and stance
----------------
* Read-only. Every remote command is a `ps`, `inspect`, `images`, `version`, `df`, or `is-active`.
  Nothing here creates, starts, prunes, or removes anything.
* Works with both runtimes the fleet uses: docker (build01) and podman (lab-web01 and the RHEL/OL
  hosts). A host may have one, both, or neither, and "neither" is a real answer worth recording.
* One SSH round-trip per host. The remote side runs a small script that prints labelled sections;
  this module parses those sections. That keeps a 20-host inventory fast and keeps the SSH surface
  to a single command shape.
* Stdlib only, Python 3.6+, so it runs on the control node and on any fleet host without installs.

Output contract
---------------
`{"generated_at": epoch, "hosts": [{"fqdn", "source", "ssh_ok", "error", "runtimes": [...],
"containers": [...], "images": [...], "storage": {...}}]}` written to stdout or `--json PATH`.
`web/sync.py` consumes it; `--check` turns it into a human-readable drift/health report.
"""

from __future__ import print_function

import argparse
import json
import os
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_REGISTRY = os.path.join(REPO_ROOT, "web", "installs.yaml")
DEFAULT_SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]

# Section markers emitted by the remote probe. Keeping them as constants means the parser and the
# probe script cannot drift apart silently.
MARKERS = ("HOST", "SSH_ERROR", "DOCKER_VERSION", "PODMAN_VERSION", "DOCKER_SERVICE",
           "PODMAN_PS", "DOCKER_PS", "PODMAN_IMAGES", "DOCKER_IMAGES", "PODMAN_DF", "DOCKER_DF")

# The remote probe. `run` prefers `sudo -n` (both docker hosts need it) and falls back to the plain
# binary (podman is often rootless), so one script works on either host without per-host config.
REMOTE_PROBE = r"""
run() { if command -v "$1" >/dev/null 2>&1; then sudo -n "$@" 2>/dev/null || "$@" 2>/dev/null || true; fi; }
# podman keeps two separate image stores on a host: root's (/var/lib/containers) and the login user's
# rootless store (~/.local/share/containers). One invocation only ever sees one of them, and which one
# depends on whether sudo is available - so on build01 the probe reported root's store and missed every
# image we build (our images live in the agent's rootless store), while on lab-web01 it reported root's
# store, which is where that container actually lives. `both` queries the login user's store and root's
# store and merges, so the console sees the union instead of whichever one sudo happened to pick.
both() { { "$@" 2>/dev/null; sudo -n "$@" 2>/dev/null; } | grep -v '^$' | sort -u; }
both_run() { if command -v "$1" >/dev/null 2>&1; then both "$@"; fi; }
echo '###HOST'; hostname -f 2>/dev/null || hostname 2>/dev/null
echo '###DOCKER_VERSION'; run docker --version
echo '###PODMAN_VERSION'; run podman --version
echo '###DOCKER_SERVICE'; systemctl is-active docker 2>/dev/null || echo unknown
echo '###PODMAN_PS'; both_run podman ps -a --format '{{.Names}}|{{.Image}}|{{.State}}|{{.Status}}|{{.ID}}|{{.Pod}}'
echo '###DOCKER_PS'; run docker ps -a --format '{{.Names}}|{{.Image}}|{{.State}}|{{.Status}}|{{.ID}}'
echo '###PODMAN_IMAGES'; both_run podman images --all --format '{{.Repository}}:{{.Tag}}|{{.ID}}|{{.Digest}}|{{.Size}}'
echo '###DOCKER_IMAGES'; run docker images --all --format '{{.Repository}}:{{.Tag}}|{{.ID}}|{{.Size}}'
echo '###PODMAN_DF'; run podman system df --format json
echo '###DOCKER_DF'; run docker system df --format json
"""


def parse_sections(raw):
    """Split a probe transcript into `{MARKER: [lines]}`, ignoring unlabelled noise.

    The probe prints one `###MARKER` line before each command's output, so a missing section means
    the command was unavailable (no docker binary) rather than that the host is broken. Anything
    before the first marker is dropped: SSH banners and sudo warnings must not become data.
    """
    sections = {}
    current = None
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("###"):
            name = stripped[3:].strip()
            current = name if name in MARKERS else None
            if current is not None:
                sections.setdefault(current, [])
            continue
        if current is None or not stripped:
            continue
        sections[current].append(stripped)
    return sections


def parse_ps_rows(lines, runtime):
    """Turn `name|image|state|status|id[|pod]` rows from `ps -a` into container records.

    Both runtimes are asked for the same field order; podman supplies an extra trailing `pod` field
    which is kept when present and left empty for docker, so the console has one shape to render.
    """
    containers = []
    for line in lines:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue
        record = {"runtime": runtime, "name": parts[0], "image": parts[1], "state": parts[2],
                  "status": parts[3], "container_id": parts[4]}
        if len(parts) > 5:
            record["pod"] = parts[5]
        containers.append(record)
    return containers


def parse_image_rows(lines):
    """Turn `repo:tag|image_id|digest|size` (or the docker 3-field form) into image records.

    Docker's `images` output has no digest column, so the digest is recorded only when the runtime
    provides one; the console uses it to compare a host's image against the registry's current
    digest, which is the only way to see that a host is running an old build under a live tag.
    """
    images = []
    by_id = {}
    for line in lines:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3:
            continue
        repo_tag, image_id = parts[0], parts[1]
        # podman prints 4 fields (repo:tag|id|digest|size); docker prints 3 (repo:tag|id|size).
        # Normalising the two shapes here is what lets the console render one table for both.
        if len(parts) >= 4:
            digest, size = parts[2], parts[3]
        else:
            digest, size = parts[2], parts[2]
        if not digest.startswith("sha256:"):
            digest = ""
        if len(parts) >= 4 and not digest:
            # a `<none>` digest column means the size moved to parts[2] in some podman versions
            size = parts[3]
        entry = by_id.get(image_id)
        if entry is None:
            entry = {"image_id": image_id, "repo_tags": [], "digest": digest, "size": size}
            by_id[image_id] = entry
            images.append(entry)
        if repo_tag and repo_tag != "<none>:<none>":
            entry["repo_tags"].append(repo_tag)
        if digest and not entry["digest"]:
            entry["digest"] = digest
    for entry in images:
        entry["fleet_filter_owned"] = any(
            "fleet-filter" in tag.lower() or "fleet_filter" in tag.lower()
            for tag in entry["repo_tags"])
    return images


def parse_df(lines):
    """Parse `system df --format json` output from either runtime into a storage record.

    The two runtimes emit the same array shape (`Type/Count/Size/Reclaimable`), so one parser serves
    both. Values are kept as the strings the runtimes print rather than parsed byte counts, because
    the console displays them verbatim and a wrong byte math is worse than an unparsed string.
    """
    text = "\n".join(lines).strip()
    if not text:
        return {}
    rows = []
    try:
        parsed = json.loads(text)
        # podman wraps the records under "Records"; docker either emits an array or, on docker >= 23,
        # one JSON object per line. All three shapes are normalised to a list of record dicts here.
        candidates = parsed if isinstance(parsed, list) else [parsed]
        for candidate in candidates:
            if isinstance(candidate, dict) and isinstance(candidate.get("Records"), list):
                rows.extend(r for r in candidate["Records"] if isinstance(r, dict))
            elif isinstance(candidate, dict):
                rows.append(candidate)
    except ValueError:
        for line in lines:
            try:
                candidate = json.loads(line)
            except ValueError:
                continue
            if isinstance(candidate, dict):
                rows.append(candidate)
    if not rows:
        return {"raw": {"size": text}}
    storage = {}
    for row in rows:
        key = str(row.get("Type", "")).lower()
        if not key:
            continue
        storage[key] = {"count": row.get("Count", row.get("TotalCount")),
                        "size": row.get("Size"), "reclaimable": row.get("Reclaimable")}
    return storage


def probe_host(fqdn, ssh_user=None, ssh_opts=None, local=False):
    """Return the inventory record for one host, probing locally when `local` else over SSH.

    SSH failure is recorded, not raised: one unreachable host must not cost the whole inventory, and
    the console needs to distinguish "no data yet" from "we tried and could not connect".
    """
    record = {"fqdn": fqdn, "source": "local" if local else "ssh"}
    if local:
        # `check_output` raises on any non-zero exit, and this probe's exit status is the status of
        # the last tool it ran. A host where one runtime exists but the invoking user cannot query it
        # (build01 under `NoNewPrivileges=yes`, where `sudo -n` cannot elevate and rootless `docker`
        # then fails) used to lose the whole inventory: the exception propagated out of `main()`, the
        # document never existed, and `web/sync.py` dropped every host's container rows. The SSH
        # branch below has always kept `exc.output` instead; the local branch now does the same, so a
        # partial probe still yields the runtimes and containers it did report.
        try:
            raw = subprocess.check_output(["/bin/sh", "-c", REMOTE_PROBE],
                                          stderr=subprocess.DEVNULL).decode("utf-8", "replace")
        except subprocess.CalledProcessError as exc:
            raw = (exc.output or b"").decode("utf-8", "replace") if exc.output else ""
            record["probe_error"] = "local probe exited %s" % exc.returncode
        except OSError as exc:
            raw = ""
            record["probe_error"] = str(exc)
    else:
        target = "%s@%s" % (ssh_user or "agent", fqdn)
        cmd = ["ssh"] + list(ssh_opts or DEFAULT_SSH_OPTS) + [target, REMOTE_PROBE]
        try:
            raw = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                          timeout=90).decode("utf-8", "replace")
        except subprocess.CalledProcessError as exc:
            raw = (exc.output or b"").decode("utf-8", "replace") if exc.output else ""
            record["ssh_error"] = "ssh exited %s" % exc.returncode
        except subprocess.TimeoutExpired:
            raw = ""
            record["ssh_error"] = "ssh timed out"
        except OSError as exc:
            raw = ""
            record["ssh_error"] = str(exc)
    sections = parse_sections(raw)
    if sections.get("HOST"):
        record["fqdn"] = sections["HOST"][0]
    runtimes = []
    for name, key in (("docker", "DOCKER_VERSION"), ("podman", "PODMAN_VERSION")):
        value = sections.get(key, [])
        if value:
            runtimes.append({"name": name, "version": value[0]})
    if sections.get("DOCKER_SERVICE"):
        record["docker_service"] = sections["DOCKER_SERVICE"][0]
    record["runtimes"] = runtimes
    containers = parse_ps_rows(sections.get("PODMAN_PS", []), "podman")
    containers += parse_ps_rows(sections.get("DOCKER_PS", []), "docker")
    record["containers"] = containers
    images = parse_image_rows(sections.get("PODMAN_IMAGES", []))
    for entry in parse_image_rows(sections.get("DOCKER_IMAGES", [])):
        if entry["image_id"] not in {i["image_id"] for i in images}:
            images.append(entry)
    record["images"] = images
    storage = {}
    podman_df = parse_df(sections.get("PODMAN_DF", []))
    docker_df = parse_df(sections.get("DOCKER_DF", []))
    if podman_df:
        storage["podman"] = podman_df
    if docker_df:
        storage["docker"] = docker_df
    record["storage"] = storage
    return record


def load_registry_hosts(path, extra_exclude=""):
    """Return `[(fqdn, ssh_user)]` from the console's install registry, minus excluded hosts.

    Two rules live here rather than at the call sites, so no caller can accidentally ignore them:
    * `container_inventory_exclude:` in the registry lists hosts we are told about but do not own.
      The registry records hosts the project knows; ownership is a separate question, and probing a
      host that belongs to somebody else is how a read-only tool becomes an unwanted dependency.
    * `--exclude` adds to that list for a single run without editing the registry.

    The registry is a flat list of simple mappings; the same fallback web/sync.py uses is repeated
    here on purpose so this script runs on any interpreter, including one without PyYAML.
    """
    hosts = []
    excluded = set(h.strip() for h in extra_exclude.split(",") if h.strip())
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    try:
        import yaml  # noqa: F401 - availability is the only question
        data = yaml.safe_load(text) or {}
        for fqdn in data.get("container_inventory_exclude") or []:
            if isinstance(fqdn, str) and fqdn.strip():
                excluded.add(fqdn.strip())
        for entry in data.get("installs", []):
            if isinstance(entry, dict) and entry.get("fqdn"):
                hosts.append((entry["fqdn"], entry.get("ssh_user") or "agent"))
    except ImportError:
        in_exclude_block = False
        current = {}
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("container_inventory_exclude:"):
                in_exclude_block = True
                continue
            if in_exclude_block and stripped.startswith("- "):
                excluded.add(stripped[2:].strip().strip('"'))
                continue
            in_exclude_block = False
            if stripped.startswith("- fqdn:"):
                if current.get("fqdn"):
                    hosts.append((current["fqdn"], current.get("ssh_user") or "agent"))
                current = {"fqdn": stripped.split(":", 1)[1].strip()}
            elif ":" in stripped and current:
                key, _, value = stripped.partition(":")
                current[key.strip()] = value.strip().strip('"')
        if current.get("fqdn"):
            hosts.append((current["fqdn"], current.get("ssh_user") or "agent"))
    return [(fqdn, user) for fqdn, user in hosts if fqdn not in excluded]


def build_inventory(hosts, include_local=True):
    """Probe every host and return the inventory document.

    `include_local` adds the control node itself (probed without SSH) because build01 runs docker
    daemons and podman images that the console should also account for.
    """
    entries = []
    if include_local:
        entries.append(probe_host(os.uname()[1].lower(), local=True))
    for fqdn, ssh_user in hosts:
        if entries and entries[0]["fqdn"] == fqdn:
            continue
        entries.append(probe_host(fqdn, ssh_user=ssh_user))
    return {"schema_version": 1, "generated_at": int(time.time()), "hosts": entries}


def summarize(inventory):
    """Return human-readable lines describing health and version drift across the inventory.

    This is the `--check` answer: per host, which runtimes exist, how many containers are running
    versus stopped, any container that is restarting or unhealthy, and the fleet-filter images the
    host holds. It exists so an operator can run one command instead of reading JSON.
    """
    lines = []
    for host in inventory.get("hosts", []):
        runtimes = ", ".join("%s %s" % (r["name"], r["version"])
                             for r in host.get("runtimes", [])) or "none detected"
        containers = host.get("containers", [])
        running = [c for c in containers if c.get("state") == "running"]
        unhealthy = [c for c in containers
                     if c.get("state") not in ("running", "exited", "created")
                     or (c.get("health") and c.get("health") not in ("healthy", ""))]
        owned = [i for i in host.get("images", []) if i.get("fleet_filter_owned")]
        lines.append("%s  [%s]" % (host.get("fqdn"), host.get("source")))
        lines.append("  runtimes: %s" % runtimes)
        if host.get("ssh_error"):
            lines.append("  ssh: %s" % host["ssh_error"])
        lines.append("  containers: %d total, %d running, %d abnormal"
                     % (len(containers), len(running), len(unhealthy)))
        for container in containers:
            lines.append("    %-38s %-14s %s" % (container.get("name", "?"),
                                                 container.get("state", "?"),
                                                 container.get("image", "?")))
        if owned:
            lines.append("  fleet-filter images: %d" % len(owned))
            for image in owned:
                lines.append("    %-52s %s %s" % (", ".join(image.get("repo_tags", []))[:52],
                                                  image.get("image_id", "?")[:12],
                                                  image.get("size", "?")))
        for runtime, storage in sorted((host.get("storage") or {}).items()):
            if not isinstance(storage, dict):
                continue
            summary = ", ".join("%s=%s" % (k, (v or {}).get("size", "?") if isinstance(v, dict)
                                           else "?")
                                for k, v in sorted(storage.items()))
            lines.append("  %s storage: %s" % (runtime, summary or "no data"))
    return lines


def build_parser():
    """Build the argument parser for the inventory CLI."""
    parser = argparse.ArgumentParser(
        description="Collect container runtime state (docker + podman) from fleet hosts.")
    parser.add_argument("--registry", default=DEFAULT_REGISTRY,
                        help="install registry to read hosts from (default: web/installs.yaml)")
    parser.add_argument("--hosts", default="",
                        help="comma-separated FQDNs; overrides --registry when set")
    parser.add_argument("--ssh-user", default=None, help="SSH user override for every host")
    parser.add_argument("--exclude", default="",
                        help="comma-separated FQDNs to skip, in addition to the registry's "
                             "container_inventory_exclude list")
    parser.add_argument("--no-local", action="store_true",
                        help="do not probe the machine this script runs on")
    parser.add_argument("--json", dest="json_out", default="-",
                        help="write the inventory JSON to PATH, or '-' for stdout")
    parser.add_argument("--check", action="store_true",
                        help="print the human-readable health/drift summary instead of JSON")
    return parser


def main(argv=None):
    """Run the inventory: probe hosts, write or print the result, and always exit 0 on success.

    Exit codes: 0 when the inventory was produced (even if some hosts were unreachable - those are
    recorded per host), 2 when the inputs are unusable (no hosts to probe).
    """
    args = build_parser().parse_args(argv)
    if args.hosts:
        hosts = [(h.strip(), args.ssh_user) for h in args.hosts.split(",") if h.strip()]
        hosts = [(fqdn, user) for fqdn, user in hosts
                 if fqdn not in set(x.strip() for x in args.exclude.split(","))]
    else:
        hosts = load_registry_hosts(args.registry, extra_exclude=args.exclude)
        if args.ssh_user:
            hosts = [(fqdn, args.ssh_user) for fqdn, _ in hosts]
    if not hosts and not args.no_local:
        hosts = []
    if not hosts and args.no_local:
        sys.stderr.write("error: no hosts to probe (registry empty and --no-local set)\n")
        return 2
    inventory = build_inventory(hosts, include_local=not args.no_local)
    if args.check:
        for line in summarize(inventory):
            print(line)
    elif args.json_out == "-":
        print(json.dumps(inventory, indent=1, sort_keys=True))
    else:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(inventory, handle, indent=1, sort_keys=True)
            handle.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
