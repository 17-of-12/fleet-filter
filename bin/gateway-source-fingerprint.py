#!/usr/bin/env python3
"""Print a content fingerprint for the gateway source tree (Bundle N6).

N6 asks for a rebuild trigger that fires on *dependency change* rather than on a schedule alone. The
question the timer has to answer is therefore "has the source that produces this artifact changed
since the last artifact was built", and the answer cannot come from git alone: an uncommitted edit is
exactly the case that must trigger a rebuild, and `git rev-parse HEAD` does not change for it.

So the fingerprint is a hash over the source itself - every file that ends up inside the built binary
plus the files that decide which dependencies are compiled. The build script records it in the
artifact JSON, and bin/rebuild-gateway.sh compares it against the artifacts already on disk.

Python 3.9-compatible (operating rule 15: the fleet's OL8 hosts ship 3.6/3.9).
"""

from __future__ import print_function

import hashlib
import os
import sys

# Files that change the produced binary, plus the ones that pin its dependencies. Anything not
# listed here cannot change the artifact, so it must not change the fingerprint either - otherwise
# editing a README would trigger a rebuild.
FIXED_FILES = (
    "Cargo.toml",
    "Cargo.lock",
    "Containerfile",
    "rustfmt.toml",
    "clippy.toml",
)
SOURCE_DIRS = ("src", "policies")


def digest_file(path):
    """Return the sha256 of one file, or None if it cannot be read."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                h.update(chunk)
    except (IOError, OSError):
        return None
    return h.hexdigest()


def collect(root):
    """Return sorted (relative_path, sha256) pairs for every fingerprinted file under root."""
    entries = []
    for name in FIXED_FILES:
        path = os.path.join(root, name)
        if os.path.isfile(path):
            entries.append((name, digest_file(path)))
    for directory in SOURCE_DIRS:
        base = os.path.join(root, directory)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d != "target")
            for filename in sorted(filenames):
                full = os.path.join(dirpath, filename)
                rel = os.path.relpath(full, root)
                entries.append((rel, digest_file(full)))
    return sorted(entries)


def fingerprint(root):
    """Return the aggregate fingerprint, or None when a listed file is unreadable."""
    entries = collect(root)
    if not entries:
        return None
    if any(sha is None for _, sha in entries):
        return None
    payload = "\0".join("{0}:{1}".join(entry) for entry in entries)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def main(argv):
    """Print the fingerprint for a gateway tree; exit non-zero if the tree is incomplete."""
    args = [a for a in argv[1:] if not a.startswith("-")]
    root = args[0] if args else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gateway")
    value = fingerprint(root)
    if value is None:
        sys.stderr.write("error: cannot fingerprint {0}\n".format(root))
        return 1
    print(value)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
