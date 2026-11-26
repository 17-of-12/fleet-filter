#!/usr/bin/env python3
"""Refuse to share a skill that carries internal material.

A skill is prose, so nothing else checks it: not the exporter's path allowlist (it copies whole
files), not the identifier guard on tracked files (that covers the repository, and a skill may be
written outside it), and not review, because a reviewer reads a diff for behaviour and this is a
paragraph that names a host.

What it refuses: estate and host identifiers, absolute paths from a personal machine, work-item
references, and the names of the build hosts. Each is either somebody else's infrastructure or a
pointer that means nothing to a reader outside this deployment.

Usage
-----
    bin/skill-lint.py skills/*.md        # exit 1 on any finding
    bin/skill-lint.py --list             # show the patterns it refuses
"""

import argparse
import re
import sys
from pathlib import Path

# (pattern, why it is refused)
REFUSED = [
    (r"(?i)example.edu", "estate domain"),
    (r"\b192\.168\.\d+\.\d+\b", "private address"),
    (r"\b198\.18\.55\.\d+\b", "lab address"),
    (r"(?i)\blab-web01\b|\bmelchior\b|\bcasper\b|\bbalthasar\b", "internal host name"),
    (r"(?i)\boperator\b|/home/[a-z]+/", "personal path"),
    (r"#\d{3,}\b", "work-item reference"),
    (r"(?i)pi-dispatch", "internal project name"),
    (r"(?i)\b(?:TODO|FIXME)\b.*\?", "unresolved question left in prose"),
]

# A skill may legitimately describe the repository it lives in.
ALLOW = re.compile(r"(?i)(?:github\.com/17-of-12|17-of-12/fleet-filter)")


def scan(path: Path) -> list:
    """Return human-readable findings for one skill file."""
    findings = []
    for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        for pattern, why in REFUSED:
            for match in re.finditer(pattern, line):
                if ALLOW.search(line):
                    continue
                findings.append("%s:%d: %s: %r" % (path, number, why, match.group(0)))
    return findings


def main(argv=None):
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Refuse to share a skill carrying internal material")
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--list", action="store_true", help="print the refused patterns")
    args = parser.parse_args(argv)

    if args.list:
        for pattern, why in REFUSED:
            print("%-52s %s" % (pattern, why))
        return 0

    files = [p for p in args.paths if p.suffix == ".md"]
    if not files:
        print("skill-lint: no skill files given", file=sys.stderr)
        return 2

    findings = []
    for path in files:
        if not path.exists():
            findings.append("%s: missing" % path)
            continue
        findings.extend(scan(path))

    if findings:
        print("skill-lint: %d finding(s) - a shared skill must not name internal material"
              % len(findings), file=sys.stderr)
        for finding in findings:
            print("  " + finding, file=sys.stderr)
        return 1

    print("skill-lint: %d skill(s) clean" % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
