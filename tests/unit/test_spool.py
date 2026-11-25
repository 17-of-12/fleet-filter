#!/usr/bin/env python3
"""
Unit tests for the claim spool contract - Bundle R1 (schema) and R2 (durable ingest rules).

Run:  python3.12 tests/unit/test_spool.py
      python3.9  tests/unit/test_spool.py      (lab-web01's runtime)
      python3.6  tests/unit/test_spool.py      (target runtime on EL8)

Scope: everything `controller/adaptive-tarpit.py drain-spool` accepts or refuses. The spool is
the only way a network-facing producer (the Stage 2 gateway, the tarpit responder) can report a
detection without holding a write handle on the authoritative store, so its contract is tested
from both sides: the record schema the producers emit, and the filesystem rules the consumer
applies.

Review/bundle coverage:
  R1  versioned claim-record schema (legacy v1, current v1, unknown versions)
  R2  ingest refuses symlinks and non-regular files, skips staging `.tmp` names, and preserves
      a malformed claim in `failed/` instead of deleting or retrying it forever
  L4  a valid claim becomes a lease and the file is consumed; an allowlisted claim is consumed
      without a lease
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONTROLLER = os.path.join(ROOT, "controller", "adaptive-tarpit.py")
# Every interpreter the project claims to support, plus whatever is running the tests.
_default = [sys.executable] + [p for p in ("/usr/bin/python3.12", "/usr/bin/python3.9", "/usr/bin/python3.6")
                               if os.path.exists(p) and p != sys.executable]
PYTHONS = [p for p in os.environ.get("AT_TEST_PYTHONS", "").split(",") if p] or _default

PASS = 0
FAIL = 0
CURRENT_PYTHON = None


def check(label, condition, detail=""):
    """Record one assertion and print it (see the note in test_ingest.py)."""
    global PASS, FAIL
    if condition:
        PASS += 1
        print("  ok   %s" % label)
    else:
        FAIL += 1
        print("  FAIL %s %s" % (label, detail))


def run(args, python=None, stdin=None):
    """Run the controller under the given interpreter, returning (rc, stdout, stderr)."""
    python = python or CURRENT_PYTHON or PYTHONS[0]
    proc = subprocess.run(
        [python, CONTROLLER] + args,
        input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def sandbox():
    """Create an isolated {db, map, spool} set so a test run cannot touch deployed state."""
    base = tempfile.mkdtemp(prefix="at-spool-")
    return {
        "base": base,
        "db": os.path.join(base, "state.db"),
        "map": os.path.join(base, "tarpit-ips.map"),
        "spool": os.path.join(base, "spool"),
        "allowlist": os.path.join(base, "allowlist"),
    }


def write_claim(env, name, payload, raw=None):
    """Place one claim file in the spool, exactly as a producer's atomic write would.

    `raw` lets a test write bytes that are not valid JSON without going through json.dump, which
    is the only way to reproduce a truncated file.
    """
    if not os.path.isdir(env["spool"]):
        os.makedirs(env["spool"])
    path = os.path.join(env["spool"], name)
    with open(path, "w") as handle:
        handle.write(raw if raw is not None else json.dumps(payload, sort_keys=True))
    return path


def drain(env, extra=None):
    """Run `drain-spool` against a sandbox and return (rc, stdout, stderr)."""
    args = ["--db", env["db"], "--map", env["map"], "--allowlist", env["allowlist"],
            "drain-spool", "--spool", env["spool"], "--render"]
    args += extra or []
    return run(args)


def test_schema_version():
    """R1: the record schema is versioned, and an unknown version is refused, not guessed."""
    cases = [
        # (schema_version value, accepted?, explanation)
        ("missing", True, "legacy v1 responder records carry no field"),
        (1, True, "current schema"),
        (2, False, "a future schema must not be parsed with v1 meanings"),
        ("1", False, "a string is not an integer version"),
        (None, False, "null is not an integer version"),
    ]
    for value, accepted, why in cases:
        env_case = sandbox()
        try:
            claim = {"subject_ip": "198.51.100.201", "verdict": "confirmed",
                     "source": "fleet-filter-gateway", "author": "lab-web01.lab",
                     "claim_key": "signature:probe_path"}
            if value != "missing":
                claim["schema_version"] = value
            write_claim(env_case, "1763100001-198.51.100.201.json", claim)
            rc, out, err = drain(env_case)
            accepted_actual = "confirmed" in out and "invalid" not in out
            check("schema_version=%r accepted (%s)" % (value, why), accepted_actual == accepted,
                  "rc=%s out=%r err=%r" % (rc, out, err))
        finally:
            shutil.rmtree(env_case["base"], ignore_errors=True)


def test_ttl_handling():
    """A supplied `ttl` is honoured; an omitted one falls back to the verdict's policy TTL.

    Both producers (the responder, the gateway) omit it on purpose, so the fallback is the normal
    path. The explicit case is covered because a producer that *does* set it must not be silently
    overridden - that is how a 5-second test lease would otherwise look like a 72-hour one.
    """
    cases = [
        # (claim ttl value, expected lease seconds, explanation)
        (5, 5, "an explicit ttl is honoured"),
        (None, 259200, "omitted ttl uses the confirmed policy TTL"),
    ]
    for value, expected, why in cases:
        env_case = sandbox()
        try:
            claim = {"schema_version": 1, "subject_ip": "198.51.100.202", "verdict": "confirmed",
                     "source": "fleet-filter-gateway", "author": "lab-web01.lab",
                     "claim_key": "signature:probe_path"}
            if value is not None:
                claim["ttl"] = value
            write_claim(env_case, "1763100002-198.51.100.202.json", claim)
            rc, out, err = drain(env_case)
            check("claim accepted (ttl=%r)" % value, rc == 0 and "198.51.100.202" in out,
                  "rc=%s out=%r err=%r" % (rc, out, err))
            rc, out, err = run(["--db", env_case["db"], "--map", env_case["map"],
                                "--allowlist", env_case["allowlist"], "list", "--json"])
            leases = json.loads(out) if rc == 0 else []
            rows = [row for row in leases if row.get("ip") == "198.51.100.202"]
            observed = (rows[0]["expires_at"] - rows[0]["created_at"]) if rows else None
            check("lease duration %s (ttl=%r)" % (why, value), observed == expected,
                  "expected %s, got %r" % (expected, observed))
            check("claim file consumed after the row exists (ttl=%r)" % value,
                  not os.path.exists(os.path.join(env_case["spool"], "1763100002-198.51.100.202.json")))
        finally:
            shutil.rmtree(env_case["base"], ignore_errors=True)


def test_malformed_is_quarantined_not_deleted():
    """R2/R3: a bad file keeps its bytes in `failed/`; deleting it would destroy the evidence."""
    env_case = sandbox()
    try:
        path = write_claim(env_case, "1763100003-198.51.100.203.json", None, raw='{"subject_ip": ')
        rc, out, err = drain(env_case)
        check("malformed claim reported", "malformed" in out, "out=%r" % out)
        check("malformed claim removed from the queue", not os.path.exists(path))
        failed = os.listdir(os.path.join(env_case["spool"], "failed"))
        check("malformed claim preserved in failed/", len(failed) == 1 and failed[0].endswith(
            "1763100003-198.51.100.203.json"), "failed=%r" % failed)
        with open(os.path.join(env_case["spool"], "failed", failed[0])) as handle:
            check("quarantined bytes intact", handle.read() == '{"subject_ip": ')
        check("drain exits non-zero when a claim failed", rc != 0, "rc=%s" % rc)
        # A second drain must not reprocess it (it is no longer in the queue) and must not fail.
        rc2, out2, err2 = drain(env_case)
        check("quarantined claim is not retried forever", rc2 == 0 and "no queued claims" in out2,
              "rc=%s out=%r" % (rc2, out2))
    finally:
        shutil.rmtree(env_case["base"], ignore_errors=True)


def test_symlink_and_tmp_are_not_ingested():
    """R2: `*.tmp` is a staging name and a symlink is not a claim, even though it reads as one."""
    env_case = sandbox()
    try:
        os.makedirs(env_case["spool"])
        # A real claim, plus a staged (tmp) write, plus a symlink wearing a .json name.
        write_claim(env_case, "1763100004-198.51.100.204.json", {
            "schema_version": 1, "subject_ip": "198.51.100.204", "verdict": "confirmed",
            "source": "fleet-filter-gateway", "author": "h", "claim_key": "signature:probe_path",
        })
        with open(os.path.join(env_case["spool"], "1763100005-198.51.100.205.json.tmp"), "w") as handle:
            handle.write("{}")
        victim = os.path.join(env_case["base"], "victim.txt")
        with open(victim, "w") as handle:
            handle.write("not a claim")
        os.symlink(victim, os.path.join(env_case["spool"], "1763100006-198.51.100.206.json"))

        rc, out, err = drain(env_case)
        check("real claim ingested", "198.51.100.204" in out, "out=%r" % out)
        check("staged .tmp file left untouched",
              os.path.exists(os.path.join(env_case["spool"], "1763100005-198.51.100.205.json.tmp")))
        check("symlinked .json not ingested",
              os.path.islink(os.path.join(env_case["spool"], "1763100006-198.51.100.206.json")))
        check("symlink target untouched", open(victim).read() == "not a claim")
        check("symlink reported on stderr", "not a regular file" in err, "err=%r" % err)
    finally:
        shutil.rmtree(env_case["base"], ignore_errors=True)


def test_allowlisted_claim_is_consumed_without_a_lease():
    """An allowlisted address must not accumulate leases, and must not be retried forever."""
    env_case = sandbox()
    try:
        with open(env_case["allowlist"], "w") as handle:
            handle.write("198.51.100.111 # gateway address\n")
        write_claim(env_case, "1763100007-198.51.100.111.json", {
            "schema_version": 1, "subject_ip": "198.51.100.111", "verdict": "confirmed",
            "source": "fleet-filter-gateway", "author": "h", "claim_key": "signature:probe_path",
        })
        rc, out, err = drain(env_case)
        check("allowlisted claim reported", "allowlist" in out and "198.51.100.111" in out, "out=%r" % out)
        check("allowlisted claim consumed",
              not os.path.exists(os.path.join(env_case["spool"], "1763100007-198.51.100.111.json")))
        rc, out, err = run(["--db", env_case["db"], "--map", env_case["map"],
                            "--allowlist", env_case["allowlist"], "list", "--json"])
        check("no lease created for an allowlisted address", "198.51.100.111" not in out, "out=%r" % out)
    finally:
        shutil.rmtree(env_case["base"], ignore_errors=True)


def test_missing_spool_is_not_an_error():
    """A producer that has never run must not break the timer."""
    env_case = sandbox()
    try:
        rc, out, err = drain(env_case)
        check("missing spool drains cleanly", rc == 0 and "no queued claims" in out,
              "rc=%s out=%r err=%r" % (rc, out, err))
    finally:
        shutil.rmtree(env_case["base"], ignore_errors=True)


def main():
    """Run every suite once per supported interpreter and report the totals."""
    global CURRENT_PYTHON
    for python in PYTHONS:
        CURRENT_PYTHON = python
        print("\n== %s ==" % python)
        test_schema_version()
        test_ttl_handling()
        test_malformed_is_quarantined_not_deleted()
        test_symlink_and_tmp_are_not_ingested()
        test_allowlisted_claim_is_consumed_without_a_lease()
        test_missing_spool_is_not_an_error()
    print("\n%d checks, %d failures" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
