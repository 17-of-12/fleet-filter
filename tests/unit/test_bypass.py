#!/usr/bin/env python3
"""Tests for the E5 emergency bypass in controller/adaptive-tarpit.py.

Covers the three properties that make a bypass safe rather than merely convenient: it must be
expressible without the responder or Wazuh, it must expire (a forgotten bypass is its own outage), and
turning it off must restore exactly the pre-bypass map.

Runs under Python 3.9 and 3.12; skips cleanly when PyYAML is unavailable.
"""

from __future__ import print_function

import importlib.util
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

try:
    import yaml  # noqa: F401
except ImportError:
    print("SKIP test_bypass.py: PyYAML unavailable for %s" % sys.version.split()[0])
    raise SystemExit(0)

SPEC = importlib.util.spec_from_file_location("adaptive_tarpit",
                                              os.path.join(ROOT, "controller", "adaptive-tarpit.py"))
at = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(at)

PASS = 0
FAIL = 0


def check(condition, label):
    """Record one assertion."""
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
    at.cmd_claim(Args(work, ip=["203.0.113.10", "203.0.113.11"], verdict="confirmed",
                      source="CVE-2026-119618/probe_path", author="pi", ttl=None, render=True))
    baseline = at.read_map_values(args.map)
    check(baseline == {"203.0.113.10": "1", "203.0.113.11": "1"},
          "baseline map quarantines both claims (allowlisted addresses are never leased, so they "
          "only appear in the map when something else claimed them)")

    # turning the bypass on requires a TTL: an unbounded bypass is a silent outage of enforcement.
    try:
        at.cmd_bypass(Args(work, state="on", ttl=None, reason="", actor="pi", render=True))
        check(False, "`bypass on` without --ttl is refused")
    except at.Error:
        check(True, "`bypass on` without --ttl is refused (cannot be forgotten)")

    at.cmd_bypass(Args(work, state="on", ttl=600, reason="drill", actor="pi", render=True))
    bypassed = at.read_map_values(args.map)
    with open(args.map) as handle:
        header = handle.read()
    check(all(value == "0" for value in bypassed.values()) and len(bypassed) == 2,
          "while active, every quarantined address renders 0 (serve normally)")
    check("E5 BYPASS ACTIVE" in header and "drill" in header,
          "the rendered map itself states that enforcement is off and why")
    at.cmd_verify(Args(work))
    check(True, "verify accepts the bypassed map (no false drift during an incident)")

    # an expired bypass must be reported as expired, then cleared by the timed `expire` run.
    expired = json.load(open(args.bypass_file))
    expired["expires_epoch"] = int(time.time()) - 1
    with open(args.bypass_file, "w") as handle:
        json.dump(expired, handle)
    state = at.bypass_state(args.bypass_file)
    check(state is not None and state.get("expired") is True,
          "an expired bypass reads back as active-but-expired rather than silently absent")
    at.cmd_expire(Args(work, render=True))
    restored = at.read_map_values(args.map)
    check(restored == baseline, "expiry restores exactly the pre-bypass map (no lost leases)")
    check(at.bypass_state(args.bypass_file) is None, "the expired bypass is cleared by `expire`")

    # explicit off, and the no-op path when nothing was ever set.
    at.cmd_bypass(Args(work, state="on", ttl=600, reason="second", actor="pi", render=True))
    at.cmd_bypass(Args(work, state="off", ttl=None, reason="", actor="pi", render=True))
    check(at.bypass_state(args.bypass_file) is None and at.read_map_values(args.map) == baseline,
          "`bypass off` restores the map and clears the state")
    at.cmd_bypass(Args(work, state="off", ttl=None, reason="", actor="pi", render=True))
    check(True, "`bypass off` with no bypass in effect is a no-op, not an error")

print("test_bypass.py: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
