#!/usr/bin/env python3
"""Tests for the PTN-14 render stamp written beside the Apache map.

Why this file exists
--------------------
PTN-14: the rendered map carries one value per address and no per-entry expiry, and `do_render`
deliberately does not rewrite a map whose entries did not change ("no spurious mtime change for
Apache's 60s cache"). Those two facts together mean the artifact's own age stops advancing while
the controller is still healthy, so a consumer holding the map cannot tell "nothing changed" from
"the controller died" - and the Stage 2 gateway's staleness rule (gateway/src/classify.rs) would
eventually treat a healthy host's map as a dead one and lift its quarantines.

The stamp answers the question the map cannot: `write_render_stamp` runs on every render, including
the idempotent one, and records when the controller last confirmed this state.

Contract pinned here (both sides depend on it):
  * a render writes `<map>.stamp` beside the map, in the format the gateway parses;
  * the idempotent render path (entries unchanged) still advances it;
  * `read_render_stamp` tolerates a missing or malformed sidecar instead of raising.

Runs under Python 3.9 and 3.12; skips cleanly when PyYAML is unavailable.
"""

from __future__ import print_function

import importlib.util
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

try:
    import yaml  # noqa: F401
except ImportError:
    print("SKIP test_render_stamp.py: PyYAML unavailable for %s" % sys.version.split()[0])
    raise SystemExit(0)

SPEC = importlib.util.spec_from_file_location("adaptive_tarpit",
                                              os.path.join(ROOT, "controller", "adaptive-tarpit.py"))
at = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(at)

PASS = 0
FAIL = 0


def check(condition, label):
    """Count and print one assertion result in the project's `ok`/`FAIL` format."""
    global PASS, FAIL
    if condition:
        PASS += 1
        print("ok   %s" % label)
    else:
        FAIL += 1
        print("FAIL %s" % label)


class Args(object):
    """Minimal stand-in for the argparse namespace the controller commands consume."""

    def __init__(self, work, **overrides):
        """Fill in the global and render options with paths inside `work`."""
        self.db = os.path.join(work, "state.db")
        self.map = os.path.join(work, "map")
        self.allowlist = os.path.join(work, "allowlist")
        self.bypass_file = os.path.join(work, "bypass.json")
        self.audit_log = os.path.join(work, "audit.jsonl")
        self.max_tarpit = at.DEFAULT_MAX_TARPIT
        self.dry_run = False
        self.allow_empty = False
        self.quiet = False
        self.render = True
        for key, value in overrides.items():
            setattr(self, key, value)


with tempfile.TemporaryDirectory() as work:
    args = Args(work)
    with open(args.allowlist, "w") as handle:
        handle.write("# test allowlist\n127.0.0.1\n")

    # --- first render: the map and its stamp are both produced --------------------------------------
    at.cmd_claim(Args(work, ip=["203.0.113.20"], verdict="confirmed",
                      source="CVE-2026-119618/probe_path", author="pi", ttl=None, render=True),
                 )
    stamp_path = args.map + at.STAMP_SUFFIX
    check(os.path.exists(args.map), "claim --render produced the map")
    check(os.path.exists(stamp_path),
          "the same render wrote the sibling stamp the Stage 2 gateway reads (PTN-14)")
    recorded = at.read_render_stamp(args.map)
    check(recorded is not None and abs(recorded - int(time.time())) <= 5,
          "the stamp records the render moment, not a copied mtime")

    # --- idempotent render: entries unchanged, stamp still advances ---------------------------------
    # `do_render` returns early when the entry set is identical, which is exactly the path that used to
    # freeze the artifact's age. The stamp has to move anyway, or "nothing changed" is indistinguishable
    # from "nobody is rendering".
    old_stamp = int(time.time()) - 86400
    with open(stamp_path, "w") as handle:
        handle.write("# fleet-filter render stamp - do not edit by hand.\nrendered_at=%d\n" % old_stamp)
    os.utime(args.map, (old_stamp, old_stamp))
    at.cmd_render(Args(work, render=True))
    check(at.read_map_values(args.map) == {"203.0.113.20": "1"},
          "the unchanged render did not rewrite the map body")
    check(at.read_render_stamp(args.map) is not None
          and at.read_render_stamp(args.map) > old_stamp,
          "the idempotent render advanced the stamp anyway (the PTN-14 freeze this fixes)")
    check(int(os.stat(args.map).st_mtime) < int(time.time()) - 3600,
          "the map's own mtime stayed frozen, which is why the stamp is needed at all")

    # --- the stamp is parseable by the gateway's reader contract --------------------------------------
    with open(stamp_path) as handle:
        body = handle.read()
    check(body.startswith("# fleet-filter render stamp"),
          "the stamp keeps the header the gateway's reader expects")
    check("rendered_at=%d" % at.read_render_stamp(args.map) in body,
          "the stamp's rendered_at field is the value the gateway parses")

    # --- reader tolerance: a missing or malformed sidecar must not raise -------------------------------
    check(at.read_render_stamp(os.path.join(work, "nonexistent.map")) is None,
          "a map with no stamp reads as 'unknown', not an exception")
    broken = os.path.join(work, "broken.map")
    with open(broken + at.STAMP_SUFFIX, "w") as handle:
        handle.write("rendered_at=not-a-number\n")
    check(at.read_render_stamp(broken) is None,
          "an unparseable stamp degrades to unknown rather than crashing the caller")

print("test_render_stamp.py: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
