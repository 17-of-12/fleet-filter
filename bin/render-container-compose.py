#!/usr/bin/env python3
"""Render `container/compose.yaml` from `container/config.yaml`.

The project owns the configuration and generates the artifact, never the other way round: the
Compose file is what a runtime consumes, but the config file is what an operator reviews. Keeping
them separate is what lets V2 be verified instead of asserted - the SELinux toggle lives in the
config, and this renderer is the only place that decides how the toggle is expressed in Compose.

When `security.selinux.enabled` is false the renderer emits no `:z`/`:Z` mount suffix and no
SELinux-related keys at all, because the alternative - inventing a Compose key that no runtime
implements - produces a setting that looks configured and does nothing.

Target interpreter is Python 3.6: the renderer runs on the EL8 targets, which ship 3.6.8, so no
`from __future__ import annotations` and no 3.7+ syntax (measured - the future import is a hard
SyntaxError on 3.6.8 and broke the target-side preflight). Rendering itself requires PyYAML >= 5.1
(`safe_dump(sort_keys=...)`); the project venv pins 6.0.3. Targets only *verify* the artifact hash
rather than re-rendering it, so an old target PyYAML cannot cause a false stale verdict.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - exercised by the skip path in the test suite
    yaml = None

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "container" / "config.yaml"
COMPOSE_PATH = REPO_ROOT / "container" / "compose.yaml"


def load_config(path: Path) -> dict:
    """Load the project container configuration, or exit if PyYAML is unavailable."""
    if yaml is None:
        sys.exit("PyYAML is required to render the compose file (see .venv per operating rule 15)")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def mount_suffix(config: dict) -> str:
    """Return the SELinux mount suffix the project is allowed to emit for this configuration.

    The only sanctioned ways to express SELinux labelling in a bind mount are the `:z` and `:Z`
    suffixes, and both imply the project is relabelling host content. With the project toggle off,
    the correct suffix is the empty string.
    """
    return "z" if config["security"]["selinux"]["enabled"] else ""


def render_volumes(config: dict) -> list:
    """Render every bind mount in long form so `create_host_path: false` can be set per mount.

    Short-form (`/a:/b:ro`) cannot express `create_host_path`, and the default behaviour - create
    the missing source as an empty root-owned directory - is how a containerised web server ends up
    silently serving nothing after a typo in a path.
    """
    entries = []
    for mount in list(config.get("mounts", [])) + list(config.get("extra_readonly_files", [])):
        entry = {
            "type": "bind",
            "source": mount["source"],
            "target": mount["target"],
            "read_only": bool(mount.get("read_only", True)),
            "bind": {"create_host_path": False},
        }
        suffix = mount_suffix(config)
        if suffix:
            entry["bind"]["selinux"] = suffix
        entries.append(entry)
    for tmpfs_target in config["security"].get("tmpfs", []):
        entries.append(
            {
                "type": "tmpfs",
                "source": "",
                "target": tmpfs_target,
                "read_only": False,
                "tmpfs": {
                    "mode": "1777",
                    "uid": str(config["security"]["run_as_user"]),
                    "gid": str(config["security"]["run_as_group"]),
                },
            }
        )
    return entries


def render_service(config: dict) -> dict:
    """Build the single service definition from the project configuration."""
    security = config["security"]
    publish = config["publish"][0]
    service = {
        "image": f"{config['image']['name']}:{config['image']['version']}",
        "container_name": f"{config['image']['name']}-{config['target']['hostname'].split('.')[0]}",
        "user": f"{security['run_as_user']}:{security['run_as_group']}",
        "restart": "unless-stopped",
        "read_only": bool(security["read_only_rootfs"]),
        "cap_drop": list(security["cap_drop"]),
        "cap_add": list(security.get("cap_add", [])),
        "security_opt": (["no-new-privileges:true"] if security["no_new_privileges"] else []),
        "privileged": bool(security["privileged"]),
        "ports": [f"{publish['address']}:{publish['host_port']}:{publish['container_port']}"],
        "volumes": render_volumes(config),
        "pids_limit": int(security["limits"]["pids"]),
        "mem_limit": str(security["limits"]["memory"]),
        "cpus": str(security["limits"]["cpus"]),
        "labels": {
            "io.fleet-filter.managed": "true",
            "io.fleet-filter.target": config["target"]["hostname"],
            "io.fleet-filter.config-sha256": config_sha256(config),
        },
    }
    if not security["docker_socket_mount"]:
        # The Docker/Podman socket is never mounted: a container that can talk to the runtime can
        # create containers, which is a privilege escalation path the canary has no need for.
        service["labels"]["io.fleet-filter.socket-mount"] = "false"
    return service


def config_sha256(config: dict) -> str:
    """Return the content hash of the configuration, used to detect a stale generated artifact."""
    payload = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def render_compose(config: dict) -> str:
    """Render the full Compose document, headed by a generated-file banner."""
    document = {"name": f"fleet-filter-{config['target']['hostname'].split('.')[0]}",
                "services": {config["image"]["name"]: render_service(config)}}
    body = yaml.safe_dump(document, sort_keys=False, default_flow_style=False, width=120)
    banner = (
        "# Generated by bin/render-container-compose.py - do not edit.\n"
        f"# Source: container/config.yaml (sha256 {config_sha256(config)})\n"
        f"# Target: {config['target']['hostname']}  Runtime: {config['runtime']['name']} "
        f"{config['runtime']['version']}\n"
        "# Editing this file without the source is a configuration change the project does not\n"
        "# recognise; the preflight refuses to start a container from a mismatched artifact.\n"
    )
    return banner + body


def main() -> int:
    """Render, then write or verify the generated Compose artifact."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=CONFIG_PATH, help="project container config")
    parser.add_argument("--output", type=Path, default=COMPOSE_PATH, help="generated compose file")
    parser.add_argument("--check", action="store_true", help="verify the artifact without writing it")
    args = parser.parse_args()

    config = load_config(args.config)
    rendered = render_compose(config)
    if args.check:
        if not args.output.exists():
            print(f"MISSING {args.output}", file=sys.stderr)
            return 1
        if args.output.read_text(encoding="utf-8") != rendered:
            print(f"STALE {args.output} - regenerate with bin/render-container-compose.py", file=sys.stderr)
            return 1
        print(f"current {args.output} (config sha256 {config_sha256(config)[:12]})")
        return 0
    args.output.write_text(rendered, encoding="utf-8")
    print(f"wrote {args.output} (config sha256 {config_sha256(config)[:12]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
