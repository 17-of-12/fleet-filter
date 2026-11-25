#!/usr/bin/env python3
"""Render one policy per host into a publish directory the hosts pull from.

Distribution is pull rather than push, for the same reason the certificate renewal is: a host behind
a load balancer, or on the wrong side of a management VLAN, cannot be reached inbound, and a
distribution scheme that only works when the control node can dial out fails exactly on the hosts
that matter. The control node writes a directory; each host fetches its own file and proves it
applied.

The hosts table is the input, not a directory scan: a host that is removed from `config/hosts.yaml`
must stop being published, or its stale policy sits there looking authoritative to whoever fetches
it next.

Every rendered file is validated by the gateway's own parser before it is published. A policy that
fails there would be a restart loop on the host that fetched it, discovered at the worst moment.

Usage:
    publish-policies.py --out /var/lib/fleet-filter/publish
    publish-policies.py --out /tmp/pub --hosts config/hosts.yaml --binary path/to/gateway
"""

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RENDERER = REPO / "bin" / "render-topology.py"

# The gateway binary is not always present (a fresh control node, a CI container). Validation is
# skipped with a warning rather than silently: publishing an unchecked policy is the thing this
# script exists to prevent, so the operator has to see that it happened.
DEFAULT_BINARY = Path.home() / ".cache" / "fleet-filter-gateway" / "target" / "release" / "fleet-filter-gateway"


def load_renderer():
    """Import bin/render-topology.py, whose name is not a valid module identifier."""
    spec = importlib.util.spec_from_file_location("render_topology", RENDERER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate(text, binary):
    """Ask the gateway's parser whether this policy is acceptable. Returns (ok, detail)."""
    if not binary.exists():
        return None, "not validated: no gateway binary at %s" % binary
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as handle:
        handle.write(text)
        path = handle.name
    try:
        result = subprocess.run([str(binary), "--policy", path, "--show-policy"],
                                capture_output=True, text=True)
        return result.returncode == 0, (result.stdout or result.stderr).strip().splitlines()[0:1]
    finally:
        Path(path).unlink(missing_ok=True)


def main(argv=None):
    """Render, validate, and write each host's policy plus a manifest of what was published."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--hosts", default=str(REPO / "config" / "hosts.yaml"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--binary", default=str(DEFAULT_BINARY))
    parser.add_argument("--signing-key", type=Path, default=None,
                        help="RSA private key; publishes a detached signature over each digest")
    parser.add_argument("--allow-unvalidated", action="store_true",
                        help="publish even when no gateway binary is available to validate with")
    args = parser.parse_args(argv)

    import yaml

    table = yaml.safe_load(Path(args.hosts).read_text()) or {}
    renderer = load_renderer()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    published, failed = [], []
    wanted = set()
    for host in table.get("hosts") or []:
        name = host["name"]
        wanted.add(name + ".toml")
        try:
            text = renderer.render_policy(
                host["topology"],
                host.get("site", name),
                host["backend"],
                cert=host.get("cert"),
                key=host.get("key"),
                trusted_proxies=tuple(host.get("trusted_proxies") or ()),
                version=host.get("version"),
                spool_dir=host.get("spool_dir", "/var/lib/fleet-filter/spool"),
                map_path=host.get("map", "/etc/fleet-filter/quarantine.map"),
                source_commit=host.get("source_commit", "published"),
                bind=host.get("bind"),
            )
        except (ValueError, KeyError) as error:
            failed.append((name, str(error)))
            continue

        ok, detail = validate(text, Path(args.binary))
        if ok is False:
            failed.append((name, "the gateway refused the policy: %s" % detail))
            continue
        if ok is None and not args.allow_unvalidated:
            # Publishing unchecked policy is the one thing this script exists to prevent, so the
            # absent binary is an error rather than a warning nobody reads.
            failed.append((name, detail + " (pass --allow-unvalidated to publish anyway)"))
            continue

        digest = hashlib.sha256(text.encode()).hexdigest()
        (out / (name + ".toml")).write_text(text)
        (out / (name + ".sha256")).write_text(digest + "\n")
        if args.signing_key:
            # Sign the digest, not the policy: the host recomputes the digest and verifies the
            # signature over the value it computed, so a swapped policy fails twice.
            signature = subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(args.signing_key),
                 str(out / (name + ".sha256"))],
                capture_output=True, check=True).stdout
            (out / (name + ".sha256.sig")).write_bytes(signature)
        published.append({"host": name, "sha256": digest, "bytes": len(text),
                          "version": host.get("version") or "%s-%s" % (host["topology"], host.get("site", name)),
                          "validated": ok is True})

    # A host removed from the table must stop being published, or its last policy stays there looking
    # current to whoever fetches it next.
    removed = []
    for stale in sorted(out.glob("*.toml")):
        if stale.name not in wanted:
            removed.append(stale.name)
            stale.unlink()
            (out / (stale.stem + ".sha256")).unlink(missing_ok=True)
            (out / (stale.stem + ".sha256.sig")).unlink(missing_ok=True)

    (out / "manifest.json").write_text(json.dumps({
        "published": published,
        "failed": [{"host": name, "error": error} for name, error in failed],
        "removed": removed,
    }, indent=2) + "\n")

    for entry in published:
        print("%-18s %s  %5d bytes  validated=%s"
              % (entry["host"], entry["sha256"][:16], entry["bytes"], entry["validated"]))
    for name, error in failed:
        print("FAILED %s: %s" % (name, error), file=sys.stderr)
    for name in removed:
        print("removed %s (no longer in the hosts table)" % name, file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
