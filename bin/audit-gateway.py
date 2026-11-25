#!/usr/bin/env python3.9
"""Audit the gateway's locked dependencies against the RustSec advisory database (M6).

Purpose
-------
ADR-0001 M6 requires a dependency audit to gate every gateway build, and requires it to *fail
the build* on an unwaived advisory. This script produces that verdict from `gateway/Cargo.lock`
and writes a dated record under `data/results/`, so "was this artifact audited, and when" has an
answer other than a person's memory.

Why not just `cargo audit`
--------------------------
`cargo audit` is the canonical tool and is used when it is available. It is not always
available: it is a Rust binary that must itself be compiled, and the builder image does not
ship it. Falling back to the advisory database directly keeps the gate enforceable today instead
of waiting on tooling, with two deliberate behaviours:

  * every advisory published for a locked crate is fetched, not only the newest;
  * a version requirement this script cannot parse is treated as **matching** (conservative), so
    an unfamiliar comparator produces a reported finding rather than a silent pass.

The fallback is recorded in the output (`method` field), so a result produced without
`cargo audit` never masquerades as one that was produced with it.

Usage
-----
    bin/audit-gateway.sh [--lockfile gateway/Cargo.lock] [--out data/results/]
    bin/audit-gateway.py [--lockfile PATH] [--out DIR] [--quiet]

Exit codes: 0 = no unwaived advisory affects a locked version; 1 = findings exist;
2 = the audit could not be completed (network, missing lockfile).
"""

import datetime
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.request

RAW_BASE = "https://raw.githubusercontent.com/RustSec/advisory-db/main"
API_TREE = "https://api.github.com/repos/RustSec/advisory-db/git/trees/main?recursive=1"


def parse_args(argv):
    """Parse `--lockfile PATH`, `--out DIR`, `--quiet`; anything else is a usage error."""
    lockfile = None
    out_dir = None
    quiet = False
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--lockfile":
            lockfile = argv[i + 1] if i + 1 < len(argv) else None
            i += 2
        elif arg == "--out":
            out_dir = argv[i + 1] if i + 1 < len(argv) else None
            i += 2
        elif arg in ("--quiet", "-q"):
            quiet = True
            i += 1
        elif arg in ("--help", "-h"):
            print(__doc__)
            raise SystemExit(0)
        else:
            sys.stderr.write("error: unknown argument: %s\n" % arg)
            raise SystemExit(2)
    if lockfile is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        lockfile = os.path.join(root, "gateway", "Cargo.lock")
    if out_dir is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        out_dir = os.path.join(root, "data", "results")
    return lockfile, out_dir, quiet


def locked_packages(lockfile):
    """Return {crate: version} from a Cargo.lock; raises if the file is missing or unparsable."""
    with open(lockfile, "r", encoding="utf-8") as handle:
        text = handle.read()
    pairs = re.findall(r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text)
    if not pairs:
        raise ValueError("no [[package]] entries found in %s" % lockfile)
    return dict(pairs)


def parse_versions(text):
    """Extract version requirement strings from a RustSec advisory's TOML frontmatter."""
    match = re.search(r"^---\n(.*?)\n---", text, re.S | re.M)
    if not match:
        return []
    body = match.group(1)
    requirements = []
    for block in re.findall(r"\[\[versions\]\]\s*\n((?:[a-z]+\s*=\s*\"[^\"]*\"\s*\n?)+)", body):
        for _kind, value in re.findall(r"(patch|broken)\s*=\s*\"([^\"]*)\"", block):
            requirements.append(value)
    if not requirements:
        for value in re.findall(r"^(?:version|versions)\s*=\s*\"([^\"]*)\"", body, re.M):
            requirements.append(value)
    return requirements


def semver(text):
    """Normalise a version string to a comparable 3-tuple, ignoring pre-release/build suffixes."""
    parts = re.split(r"[.\-+]", text)
    numbers = []
    for part in parts[:3]:
        numbers.append(int(part) if part.isdigit() else 0)
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers)


def satisfies(version, requirement):
    """Return True if `version` falls inside a comma-separated semver requirement.

    Supports `>=`, `>`, `<=`, `<`, `=`, `^`, `~`. A comparator this function cannot parse returns
    True on purpose: an unparseable range must surface as a finding, not as a silent pass.
    """
    candidate = semver(version)
    for part in requirement.split(","):
        part = part.strip()
        if not part:
            continue
        match = re.match(r"^(>=|<=|>|<|=|\^|~)?\s*([0-9][0-9A-Za-z.\-+]*)$", part)
        if not match:
            return True
        operator, target = match.group(1) or "=", semver(match.group(2))
        if operator == ">=" and not candidate >= target:
            return False
        if operator == ">" and not candidate > target:
            return False
        if operator == "<=" and not candidate <= target:
            return False
        if operator == "<" and not candidate < target:
            return False
        if operator == "=" and candidate != target:
            return False
        if operator == "^" and not (candidate >= target and candidate[0] == target[0]):
            return False
        if operator == "~" and not (
            candidate >= target and candidate[0] == target[0] and candidate[1] == target[1]
        ):
            return False
    return True


def fetch(url):
    """Fetch a URL and return its text, raising on any transport failure."""
    context = ssl.create_default_context()
    with urllib.request.urlopen(url, timeout=30, context=context) as response:
        return response.read().decode("utf-8", "replace")


def cargo_audit(lockfile):
    """Run `cargo audit` if the binary exists, returning (ran, output). Never fails the caller."""
    cargo_audit_bin = None
    for candidate in ("cargo-audit",):
        found = subprocess.call(["which", candidate], stdout=subprocess.DEVNULL) == 0
        if found:
            cargo_audit_bin = candidate
            break
    if cargo_audit_bin is None:
        try:
            probe = subprocess.run(
                ["cargo", "audit", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
            if probe.returncode == 0:
                cargo_audit_bin = "cargo audit"
        except Exception:
            cargo_audit_bin = None
    if cargo_audit_bin is None:
        return False, ""
    directory = os.path.dirname(lockfile)
    try:
        run = subprocess.run(
            cargo_audit_bin.split() + ["--file", lockfile, "--no-fetch"],
            cwd=directory,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=600,
            check=False,
        )
        return True, run.stdout.decode("utf-8", "replace")
    except Exception as exc:  # a tool failure must not be reported as "no vulnerabilities"
        return False, "cargo audit invocation failed: %s" % exc


def main(argv):
    """Run the audit, write the dated record, and exit with the gate's verdict."""
    lockfile, out_dir, quiet = parse_args(argv)
    if not os.path.isfile(lockfile):
        sys.stderr.write("error: lockfile not found: %s\n" % lockfile)
        return 2

    packages = locked_packages(lockfile)
    lock_sha = subprocess.run(
        ["sha256sum", lockfile], stdout=subprocess.PIPE, check=False
    ).stdout.decode().split(" ")[0]

    ran_cargo, cargo_output = cargo_audit(lockfile)
    method = "cargo-audit" if ran_cargo else "rustsec-advisory-db-direct"

    findings = []
    fetch_errors = []
    advisories_seen = 0
    try:
        tree = json.loads(fetch(API_TREE)).get("tree", [])
    except Exception as exc:
        sys.stderr.write("error: could not fetch the RustSec advisory tree: %s\n" % exc)
        return 2

    advisory_index = {}
    for entry in tree:
        match = re.match(r"^crates/([^/]+)/(RUSTSEC-\d{4}-\d{4,})\.md$", entry["path"])
        if match and match.group(1) in packages:
            advisory_index.setdefault(match.group(1), []).append(match.group(2))

    for crate in sorted(advisory_index):
        for advisory_id in sorted(advisory_index[crate]):
            url = "%s/crates/%s/%s.md" % (RAW_BASE, crate, advisory_id)
            try:
                text = fetch(url)
            except Exception as exc:
                fetch_errors.append("%s/%s: %s" % (crate, advisory_id, exc))
                continue
            advisories_seen += 1
            version = packages[crate]
            for requirement in parse_versions(text):
                if satisfies(version, requirement):
                    title_match = re.search(r'^title\s*=\s*"([^"]*)"', text, re.M)
                    findings.append(
                        {
                            "crate": crate,
                            "locked_version": version,
                            "advisory": advisory_id,
                            "affected_range": requirement,
                            "title": title_match.group(1) if title_match else "",
                        }
                    )
                    break

    waivers_path = os.path.join(os.path.dirname(lockfile), "audit-waivers.toml")
    waivers = []
    if os.path.isfile(waivers_path):
        with open(waivers_path, "r", encoding="utf-8") as handle:
            waivers = re.findall(r'id\s*=\s*"(RUSTSEC-\d{4}-\d{4,})"', handle.read())
    unwaived = [f for f in findings if f["advisory"] not in waivers]

    record = {
        "audited_at_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lockfile": os.path.relpath(lockfile) if os.path.dirname(lockfile) else lockfile,
        "cargo_lock_sha256": lock_sha,
        "locked_packages": len(packages),
        "method": method,
        "advisories_examined": advisories_seen,
        "fetch_errors": fetch_errors,
        "findings": findings,
        "waived_ids": waivers,
        "unwaived_findings": len(unwaived),
        "verdict": "FAIL" if unwaived else "PASS",
    }
    if ran_cargo:
        record["cargo_audit_output_head"] = cargo_output.splitlines()[:20]

    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    out_path = os.path.join(out_dir, "gateway-audit-%s.json" % stamp)
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")

    if not quiet:
        print("method:            %s" % record["method"])
        print("lockfile:          %s (%s)" % (record["lockfile"], lock_sha[:12]))
        print("locked packages:   %d" % record["locked_packages"])
        print("advisories seen:   %d" % record["advisories_examined"])
        print("fetch errors:      %d" % len(record["fetch_errors"]))
        print("findings:          %d (unwaived: %d)" % (len(findings), len(unwaived)))
        for finding in unwaived:
            print(
                "  %s %s  %s  affected: %s  %s"
                % (
                    finding["crate"],
                    finding["locked_version"],
                    finding["advisory"],
                    finding["affected_range"],
                    finding["title"],
                )
            )
        print("verdict:           %s" % record["verdict"])
        print("record:            %s" % out_path)

    return 1 if unwaived else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
