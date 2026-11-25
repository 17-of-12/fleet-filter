#!/usr/bin/env python3
"""Answer "what is running where" for the lab, and compare it with what was declared.

Purpose
-------
The lab is three hosts, three containers and a set of listener ports, and every question about it
used to cost three SSH sessions and a paragraph of context. This script is the deterministic lever:
one command, one table, one exit code. It compares `lab/manifest.json` (what the project intends to
be running, with the CVE each victim carries) against what the hosts actually report, and calls the
difference drift - the same intent-vs-reality check `bin/harvest-host-state.sh` performs for units.

Why a manifest rather than discovery alone: "a container called ff-httpd-2.4.49 is running" is not
the same claim as "the host that carries CVE-2021-41773 is up on 8081". The manifest states the
second, and the script reports where the first and second disagree. Discovery is read-only: podman
ps/images and ss -ltn, nothing is started, stopped or written on the target.

Design notes
------------
* Read-only. Every remote command is a listing; `sudo -n podman` is used because the victims run
  rootful, which is a deployment choice recorded in the lab host inventory.
* The parsers and the comparison are pure functions over captured text, so the tests exercise the
  real logic against fixtures instead of requiring a lab (rule 17: the fixture is the oracle).
* `--json` exists so the next command can consume the answer. A human table and a machine document
  are two renderings of one structure rather than two code paths.
* Exit code is the contract: 0 means declared and observed agree, 1 means drift (a missing
  container, a wrong image, a port that is not listening), 2 means the manifest or a host is
  unreadable. A script that cannot tell those apart is a script whose output nobody can gate on.

Usage
-----
    bin/lab-inventory.py                 # table, drift highlighted
    bin/lab-inventory.py --json          # machine-readable inventory
    bin/lab-inventory.py --manifest lab/manifest.json --ssh-key ~/.ssh/fleet_dispatch_key
    bin/lab-inventory.py --hosts ff-apache01   # one host (repeatable)
"""

import argparse
import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MANIFEST = os.path.join(REPO_ROOT, "lab", "manifest.json")
DEFAULT_KEY = os.path.expanduser("~/.ssh/fleet_dispatch_key")


def parse_containers(text):
    """Parse `podman ps --format` lines into {name: image} for running containers.

    The format string used by the caller is `{{.Names}}|{{.Image}}|{{.Status}}`, one per line. A
    line without two pipes is ignored rather than guessed at, because a renamed container or a
    changed format should show up as a missing victim, not as a container with a nonsense name.
    """
    containers = {}
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) != 3:
            continue
        name, image, status = (part.strip() for part in parts)
        if name:
            containers[name] = {"image": image, "status": status}
    return containers


def parse_images(text):
    """Parse `podman images --format '{{.Repository}}:{{.Tag}}|{{.Digest}}'` into {name: digest}."""
    images = {}
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) != 2:
            continue
        name, digest = (part.strip() for part in parts)
        if name and ":" in name:
            images[name] = digest
    return images


def parse_listeners(text):
    """Parse `ss -ltnH` output into a sorted list of listening ports.

    `-H` suppresses the header so every line is data. The local address is the fourth column and may
    be `0.0.0.0:8080`, `[::]:8443` or `127.0.0.1:8081`; only the port matters here, and a line whose
    address has no colon is skipped rather than crashing the inventory.
    """
    ports = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        address = fields[3]
        if ":" not in address:
            continue
        port = address.rsplit(":", 1)[1]
        if port.isdigit():
            ports.add(int(port))
    return sorted(ports)


def compare(host_entry, observed):
    """Return the drift between one host's declared expectations and what it reported.

    Every finding is a sentence a human can act on, because the exit code is 1 for any of them and
    the table prints them verbatim. Three kinds: a declared container that is not running, a running
    container whose image differs from the declaration, and a declared port that is not listening.
    """
    findings = []
    containers = observed.get("containers", {})
    ports = set(observed.get("ports", []))
    for expected in host_entry.get("expected", []):
        name = expected["container"]
        running = containers.get(name)
        if running is None:
            findings.append("%s: %s is not running" % (host_entry["name"], name))
            continue
        if not running["image"].endswith(expected["image"]):
            findings.append(
                "%s: %s runs %s, declared %s"
                % (host_entry["name"], name, running["image"], expected["image"])
            )
        for port in expected.get("ports", []):
            if port not in ports:
                findings.append("%s: %s declares port %d, nothing listening" % (host_entry["name"], name, port))
    return findings


def ssh_text(host, command, key, timeout=20):
    """Run one read-only command over SSH and return its stdout, or raise RuntimeError.

    BatchMode and ConnectTimeout keep a down host from costing the caller a minute, and the key is
    passed explicitly so the result does not depend on the caller's ssh config.
    """
    argv = [
        "ssh", "-i", key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
        "-o", "StrictHostKeyChecking=accept-new", "operator@%s" % host, command,
    ]
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("%s: %s" % (host, exc))
    if proc.returncode != 0:
        raise RuntimeError("%s: %s" % (host, proc.stderr.decode("utf-8", "replace").strip()))
    return proc.stdout.decode("utf-8", "replace")


def observe(host_entry, key):
    """Collect one host's containers, images and listeners; a failure is recorded, not raised.

    A down host must not remove the other two from the table, so the error becomes part of the
    observation and `compare` reports the host as unreadable rather than as clean.
    """
    host = host_entry["ip"]
    try:
        containers = parse_containers(
            ssh_text(host, "sudo -n podman ps --format '{{.Names}}|{{.Image}}|{{.Status}}'", key)
        )
        images = parse_images(
            ssh_text(host, "sudo -n podman images --format '{{.Repository}}:{{.Tag}}|{{.Digest}}'", key)
        )
        ports = parse_listeners(ssh_text(host, "ss -ltnH", key))
    except RuntimeError as exc:
        return {"error": str(exc), "containers": {}, "images": {}, "ports": []}
    return {"error": "", "containers": containers, "images": images, "ports": ports}


def build(manifest, key, only=None):
    """Build the full inventory structure from a manifest, optionally limited to named hosts."""
    rows = []
    for host_entry in manifest.get("hosts", []):
        if only and host_entry["name"] not in only:
            continue
        observed = observe(host_entry, key)
        findings = compare(host_entry, observed)
        if observed.get("error"):
            findings.insert(0, "%s: unreadable (%s)" % (host_entry["name"], observed["error"]))
        rows.append({
            "name": host_entry["name"],
            "ip": host_entry["ip"],
            "role": host_entry.get("role", ""),
            "observed": observed,
            "findings": findings,
        })
    return {"schema": 1, "hosts": rows}


def render(inventory):
    """Render the inventory as the table a human reads, ending with a drift summary line."""
    lines = ["%-13s %-15s %-8s %s" % ("HOST", "IP", "ROLE", "RUNNING (image, ports)")]
    for row in inventory["hosts"]:
        observed = row["observed"]
        if observed.get("error"):
            lines.append("%-13s %-15s %-8s UNREADABLE: %s" % (row["name"], row["ip"], row["role"], observed["error"]))
            continue
        containers = observed["containers"]
        if not containers:
            lines.append("%-13s %-15s %-8s (nothing running)" % (row["name"], row["ip"], row["role"]))
        for index, (name, info) in enumerate(sorted(containers.items())):
            label = row["name"] if index == 0 else ""
            ip = row["ip"] if index == 0 else ""
            role = row["role"] if index == 0 else ""
            lines.append("%-13s %-15s %-8s %s (%s) ports=%s"
                         % (label, ip, role, name, info["image"], ",".join(str(p) for p in observed["ports"])))
    findings = [finding for row in inventory["hosts"] for finding in row["findings"]]
    lines.append("")
    if findings:
        lines.append("drift: %d finding(s)" % len(findings))
        for finding in findings:
            lines.append("  - %s" % finding)
    else:
        lines.append("drift: none - declared and observed agree")
    return "\n".join(lines)


def main(argv=None):
    """Parse arguments, build the inventory, print it and exit 0/1/2 by the contract in the docstring."""
    parser = argparse.ArgumentParser(description="Inventory the fleet-filter lab against lab/manifest.json")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--ssh-key", default=DEFAULT_KEY)
    parser.add_argument("--json", action="store_true", help="emit the inventory as JSON")
    parser.add_argument("--hosts", action="append", help="limit to a host name (repeatable)")
    args = parser.parse_args(argv)

    try:
        with open(args.manifest) as handle:
            manifest = json.load(handle)
    except (OSError, ValueError) as exc:
        sys.stderr.write("manifest %s: %s\n" % (args.manifest, exc))
        return 2

    inventory = build(manifest, args.ssh_key, only=args.hosts)
    if args.json:
        sys.stdout.write(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render(inventory) + "\n")
    findings = [finding for row in inventory["hosts"] for finding in row["findings"]]
    unreadable = any(row["observed"].get("error") for row in inventory["hosts"])
    if unreadable:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
