#!/usr/bin/env python3
"""Tests for the E13 controller audit log in controller/adaptive-tarpit.py.

The audit log is how Path A (exploit signatures) becomes visible to Path B (Wazuh behaviour), so the
properties under test are the ones Wazuh depends on: one parseable object per address, every address
the command touched, and a failure to write that degrades loudly instead of failing the command.

Runs under Python 3.9 and 3.12; skips cleanly when PyYAML is unavailable.
"""

from __future__ import print_function

import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

try:
    import yaml  # noqa: F401
except ImportError:
    print("SKIP test_audit.py: PyYAML unavailable for %s" % sys.version.split()[0])
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
        """Fill in the global options with paths inside `work`, overridable per test."""
        self.db = os.path.join(work, "state.db")
        self.map = os.path.join(work, "map")
        self.allowlist = os.path.join(work, "allowlist")
        self.bypass_file = os.path.join(work, "bypass.json")
        self.audit_log = os.path.join(work, "audit.jsonl")
        self.audit = True
        self.max_tarpit = at.DEFAULT_MAX_TARPIT
        self.dry_run = False
        self.allow_empty = False
        self.quiet = False
        self.render = True
        for key, value in overrides.items():
            setattr(self, key, value)


def read_records(path):
    """Parse the audit log, one JSON object per line ([] when the file does not exist)."""
    if not os.path.exists(path):
        return []
    with open(path) as handle:
        return [json.loads(line) for line in handle if line.strip()]


with tempfile.TemporaryDirectory() as work:
    args = Args(work)
    with open(args.allowlist, "w") as handle:
        handle.write("# test allowlist\n127.0.0.1\n")

    at.cmd_claim(Args(work, ip=["203.0.113.10", "203.0.113.11"], verdict="confirmed",
                      source="CVE-2026-119618/probe_path", author="pi", ttl=None, render=True))
    records = read_records(args.audit_log)
    check(len(records) == 2, "one audit line per address, not one per command")
    check(all({"schema", "ts", "host", "event", "ip", "verdict", "source", "author"} <= set(r)
              for r in records),
          "every record carries the fields Wazuh correlates on (address, verdict, source, host, ts)")
    check(sorted(r["ip"] for r in records) == ["203.0.113.10", "203.0.113.11"],
          "the recorded addresses are the ones the command acted on")
    check(all(r["schema"] == at.AUDIT_SCHEMA for r in records), "records are versioned (schema field)")

    # an allowlisted address is skipped by the claim, and that suppression must still be visible.
    at.cmd_claim(Args(work, ip=["127.0.0.1"], verdict="confirmed", source="CVE-2026-119618/probe_path",
                      author="pi", ttl=None, render=True))
    suppressed = [r for r in read_records(args.audit_log) if r["ip"] == "127.0.0.1"]
    check(len(suppressed) == 1 and suppressed[0]["result"] == "allowlisted",
          "allowlisted suppression is emitted, so the feed does not hide what the controller refused")

    at.cmd_revoke(Args(work, ip="203.0.113.10", claim_key=None, render=True))
    revoked = [r for r in read_records(args.audit_log) if r["event"] == "revoke"]
    check(len(revoked) == 1 and revoked[0]["ip"] == "203.0.113.10" and revoked[0]["scope"] == "all",
          "revoke is recorded with its scope (one claim vs every claim)")

    # --no-audit: a rehearsal must not write to the production feed.
    before = len(read_records(args.audit_log))
    at.cmd_claim(Args(work, ip=["203.0.113.20"], verdict="suspect", source="x", author="pi",
                      ttl=None, render=True, audit=False))
    check(len(read_records(args.audit_log)) == before, "--no-audit suppresses the line (dry runs stay dry)")

    # a broken audit destination must warn, not fail: the claim itself already succeeded.
    # a plain file used as the parent directory: makedirs cannot create a directory under a file,
    # which is the cheapest portable way to force a real write failure.
    blocker = os.path.join(work, "blocker")
    open(blocker, "w").close()
    broken = Args(work, ip=["203.0.113.30"], verdict="confirmed", source="x", author="pi", ttl=None,
                  render=False, audit_log=os.path.join(blocker, "audit.jsonl"))
    try:
        rc = at.cmd_claim(broken)
        check(rc == 0, "an unwritable audit log does not fail the command (state change stands)")
    except Exception as exc:  # noqa: BLE001 - any raise is the regression
        check(False, "an unwritable audit log does not fail the command (raised %s)" % exc)

print("test_audit.py: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
