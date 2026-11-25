#!/usr/bin/env python3
"""Tests for the H4 escalation ladder (controller/ladder.py) and its use in `claim`.

Two layers are covered deliberately. The pure function is where the policy lives, so every rung and
every terminal mode can be asserted without a database; the store layer is where the policy is
*applied*, and its failure mode - a lease whose length no longer matches any documented rung, or a
history table that resets and makes every address look new - is only visible end to end.

Runs under Python 3.9 and 3.12.
"""

from __future__ import print_function

import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

SPEC = importlib.util.spec_from_file_location("adaptive_tarpit",
                                              os.path.join(ROOT, "controller", "adaptive-tarpit.py"))
at = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(at)
ladder = at.ladder_mod

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


def expect_error(func, label):
    """Assert a call raises LadderError."""
    try:
        func()
    except ladder.LadderError:
        check(True, label)
    except Exception as exc:  # wrong exception type is a failure, not a pass
        check(False, "%s (raised %s)" % (label, type(exc).__name__))
    else:
        check(False, label)


class Args(object):
    """Minimal stand-in for the argparse namespace `claim` consumes."""

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
        self.ttl = None
        self.author = "pi"
        self.source = "CVE-2026-119618/probe_path"
        self.ladder_terminal = ladder.DEFAULT_TERMINAL
        for key, value in overrides.items():
            setattr(self, key, value)


def read_records(path):
    """Parse the audit log, one JSON object per line ([] when the file does not exist)."""
    if not os.path.exists(path):
        return []
    with open(path) as handle:
        return [json.loads(line) for line in handle if line.strip()]


def active_claims(store, ip):
    """Unexpired claim rows the store holds for one address."""
    return [row for row in store.claims() if row["ip"] == ip]


# --- the policy function --------------------------------------------------------------------------
check([(ladder.RUNGS[n][0], ladder.RUNGS[n][1]) for n in sorted(ladder.RUNGS)]
      == [("24h", 86400), ("48h", 172800), ("72h", 259200)],
      "the documented rungs are exactly 24h -> 48h -> 72h (owner rule 2026-11-16)")

d0 = ladder.resolve(0)
check(d0["rung"] == "24h" and d0["ttl"] == 86400 and d0["reason_code"] == "first_observation",
      "a first suspect claim earns 24h and says so")
check(ladder.resolve(1)["ttl"] == 172800 and ladder.resolve(1)["reason_code"] == "repeat_observation",
      "the second claim escalates to 48h")
check(ladder.resolve(2)["ttl"] == 259200 and ladder.resolve(2)["reason_code"] == "repeat_observation",
      "the third claim escalates to 72h")
check(ladder.resolve(3)["reason_code"] == "ladder_exhausted_cap" and ladder.resolve(3)["ttl"] == 259200,
      "the fourth claim with terminal=cap holds at 72h instead of escalating")
check(ladder.resolve(9)["ttl"] == 259200 and ladder.resolve(9)["reason_code"] == "ladder_exhausted_cap",
      "the cap is stable: the tenth claim is still 72h, not an unbounded rung")

rel = ladder.resolve(3, terminal="release")
check(rel["action"] == "release" and rel["ttl"] == 0 and rel["rung"] == "dropped"
      and rel["reason_code"] == "ladder_exhausted_release",
      "terminal=release turns the exhausted ladder into an ended quarantine, not a lease")
hb = ladder.resolve(3, terminal="hardblock")
check(hb["ttl"] == ladder.CONFIRMED_TTL and hb["reason_code"] == "ladder_exhausted_hardblock",
      "terminal=hardblock holds the address for the confirmed TTL")

conf = ladder.resolve(7, verdict="confirmed")
check(conf["rung"] == "confirmed" and conf["ttl"] == ladder.CONFIRMED_TTL
      and conf["reason_code"] == "confirmed_lease",
      "a confirmed verdict takes its 72h lease directly and never walks the suspect rungs")

expect_error(lambda: ladder.resolve(-1), "a negative prior_claims is refused")
expect_error(lambda: ladder.resolve(0, verdict="maybe"), "an unknown verdict is refused")
expect_error(lambda: ladder.resolve(0, terminal="nuke"), "an unknown terminal mode is refused")

# --- the store, where the policy is applied -------------------------------------------------------
with tempfile.TemporaryDirectory() as work:
    with open(os.path.join(work, "allowlist"), "w") as handle:
        handle.write("# empty\n")

    store = at.Store(os.path.join(work, "state.db"))
    check(store.ladder_state("203.0.113.44") is None, "an unseen address has no ladder row")

    # Four suspect claims from four different sources: 15m, 30m, 60m, then the terminal rung.
    for index, source in enumerate(["s1", "s2", "s3", "s4"]):
        at.cmd_claim(Args(work, ip=["203.0.113.44"], verdict="suspect", source=source))
    rows = read_records(os.path.join(work, "audit.jsonl"))
    claim_rows = [r for r in rows if r["event"] == "claim" and r["ip"] == "203.0.113.44"]
    check([r["ttl"] for r in claim_rows] == [86400, 172800, 259200, 259200],
          "four claims from four sources lease 24h, 48h, 72h, 72h in that order")
    check([r["ladder_rung"] for r in claim_rows] == ["24h", "48h", "72h", "72h"],
          "each audit line names the rung it used")
    check([r["ladder_reason"] for r in claim_rows]
          == ["first_observation", "repeat_observation", "repeat_observation",
              "ladder_exhausted_cap"],
          "each audit line names the reason for the transition")
    check([r["prior_claims"] for r in claim_rows] == [0, 1, 2, 3],
          "the audit line reports how many prior claims the decision was based on")
    state = store.ladder_state("203.0.113.44")
    check(state["claims"] == 4 and state["rung"] == "72h",
          "the ladder table records four claims at the top rung")

    # An explicit --ttl is the operator overriding the ladder, and must not advance it.
    at.cmd_claim(Args(work, ip=["203.0.113.55"], verdict="suspect", source="s1", ttl=1234))
    row = [r for r in read_records(os.path.join(work, "audit.jsonl"))
           if r["ip"] == "203.0.113.55"][0]
    check(row["ttl"] == 1234 and "ladder_rung" not in row,
          "an explicit --ttl is honoured and records no rung, because the ladder did not decide")
    check(store.ladder_state("203.0.113.55") is None,
          "an explicit --ttl does not create ladder history")

    # terminal=release: the fourth claim ends the quarantine instead of extending it.
    at.cmd_claim(Args(work, ip=["203.0.113.66"], verdict="suspect", source="s1",
                      ladder_terminal="release"))
    at.cmd_claim(Args(work, ip=["203.0.113.66"], verdict="suspect", source="s2",
                      ladder_terminal="release"))
    at.cmd_claim(Args(work, ip=["203.0.113.66"], verdict="suspect", source="s3",
                      ladder_terminal="release"))
    check(len(active_claims(store, "203.0.113.66")) == 3, "three claims still hold a lease")
    at.cmd_claim(Args(work, ip=["203.0.113.66"], verdict="suspect", source="s4",
                      ladder_terminal="release"))
    check(active_claims(store, "203.0.113.66") == [],
          "the fourth claim with terminal=release removes every claim for the address")
    release_row = [r for r in read_records(os.path.join(work, "audit.jsonl"))
                   if r["ip"] == "203.0.113.66"][-1]
    check(release_row["result"] == "released" and release_row["ladder_rung"] == "dropped",
          "the release is audited as released/dropped rather than as a lease")

    # A confirmed claim still records its rung, so the audit vocabulary is uniform.
    at.cmd_claim(Args(work, ip=["203.0.113.77"], verdict="confirmed", source="s1"))
    conf_row = [r for r in read_records(os.path.join(work, "audit.jsonl"))
                if r["ip"] == "203.0.113.77"][0]
    check(conf_row["ladder_rung"] == "confirmed" and conf_row["ttl"] == ladder.CONFIRMED_TTL,
          "a confirmed claim audits rung `confirmed` with the 24h TTL")

print("test_ladder.py: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
