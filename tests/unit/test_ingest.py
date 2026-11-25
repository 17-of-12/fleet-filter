#!/usr/bin/env python3
"""
Unit tests for the `adaptive-tarpit ingest` path - the Wazuh active-response contract.

Run:  python3.12 tests/unit/test_ingest.py
      python3.9  tests/unit/test_ingest.py      (lab-web01's runtime)
      python3.6  tests/unit/test_ingest.py      (target runtime on EL8)

Covers the payload shapes the controller can actually receive, the verdict rules, and
the safety guards (loop prevention, allowlist, agent binding, idempotency).

Review remediation covered (Fleet-Filter-code-review-2026-11-14.md):
  PT-01  rendering an authoritative empty store without --allow-empty
  PT-02  Wazuh 4.x envelope, raw alert, array payload, multi-line payload, delete events
  PT-05  multi-source claims, promotion, per-claim revoke, v1 store migration
  PT-09  confirmed requires a validated rule id or an explicit verdict, not a level
  PT-11  `verify` detects map drift
  PT-04  the tarpit quota is honoured on every render path
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONTROLLER = os.path.join(ROOT, "controller", "adaptive-tarpit.py")
# Every interpreter the project claims to support, plus whatever is running the tests.
# Override with AT_TEST_PYTHONS="/usr/bin/python3.9" to exercise one runtime.
_default = [sys.executable] + [p for p in ("/usr/bin/python3.12", "/usr/bin/python3.9", "/usr/bin/python3.6")
                               if os.path.exists(p) and p != sys.executable]
PYTHONS = [p for p in os.environ.get("AT_TEST_PYTHONS", "").split(",") if p] or _default

PASS = 0
FAIL = 0
CURRENT_PYTHON = None


def check(label, condition, detail=""):
    """Record one assertion and print it.

    Accumulates into the module-level PASS/FAIL counters rather than raising, so a single
    run reports every broken behaviour instead of stopping at the first one. `detail` is
    printed only on failure - it is the diagnostic that makes the failure actionable.
    """
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


def alert(rule_id, level, srcip, location="/var/log/httpd/access_log", agent_id="206434", groups=None):
    """Build a Wazuh-shaped alert object for the fixtures to feed the controller.

    Defaults mirror the real lab-web01 agent (id 206434) and the real stock group names
    (`accesslog`, not `web-accesslog`), because a fixture that invents its own field names
    tests the fixture rather than the parser.
    """
    return {
        "timestamp": "2026-11-12T18:45:12.000Z",
        "rule": {"level": level, "description": "test rule", "id": str(rule_id),
                 "firedtimes": 1, "groups": groups or ["web", "accesslog"]},
        "agent": {"id": agent_id, "name": "lab-web01.lab", "ip": "10.30.72.19"},
        "manager": {"name": "estate-01.lab"},
        "id": "1700000000.000001",
        "full_log": '%s - - [12/Nov/2026:18:45:12 +0000] "GET /x HTTP/1.1" 404 196 "-" "curl/7.61.1"' % srcip,
        "data": {"srcip": srcip, "srcport": "57562", "protocol": "HTTP/1.1"},
        "location": location,
    }


def envelope(alert_obj, command="add"):
    """PT-02 - the Wazuh 4.x active-response envelope actually delivered on the pipe."""
    return {"version": 1,
            "origin": {"name": "lab-web01.lab", "module": "wazuh", "gid": "000"},
            "command": command,
            "parameters": {"extra_args": [], "alert": alert_obj,
                           "program": "/var/ossec/active-response/bin/fleet-filter.sh"}}


def read_map(path):
    """Return a rendered map's raw text, or None when the file does not exist.

    Returns None rather than "" so a test can distinguish "never rendered" from "rendered
    empty" - the distinction PT-01 turned on.
    """
    if not os.path.exists(path):
        return None
    with open(path) as handle:
        return handle.read()


def main():
    """Run the whole ingest suite once per available Python interpreter.

    Each interpreter gets its own temporary sandbox: sharing one `state.db` across passes
    made the second interpreter's run inherit the first one's claims and fail spuriously.
    Exits non-zero if any interpreter reports a failure.
    """
    root = tempfile.mkdtemp(prefix="at-ingest-")
    try:
        global CURRENT_PYTHON
        for python in PYTHONS:
            CURRENT_PYTHON = python
            # One sandbox per interpreter: a shared state.db would leak the first pass's
            # claims into the second and turn adds into no-ops.
            work = tempfile.mkdtemp(prefix=os.path.basename(python) + "-", dir=root)
            version = subprocess.run([python, "-V"], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, universal_newlines=True).stdout.strip()
            print("\n=== interpreter: %s (%s) ===" % (os.path.basename(python), version))

            db = os.path.join(work, "state.db")
            mp = os.path.join(work, "tarpit-ips.map")
            allowlist = os.path.join(work, "allowlist")
            open(allowlist, "w").close()
            base = ["--db", db, "--map", mp, "--allowlist", allowlist]

            # 1. Wazuh 4.x active-response envelope (PT-02: the shape actually delivered)
            rc, out, err = run(base + ["ingest", "--render"],
                               stdin=json.dumps(envelope(alert(5715, 5, "198.51.100.10"))))
            check("1  4.x envelope ingests (rc=%d) %s" % (rc, err.strip()), rc == 0)
            check("1  records 198.51.100.10", "198.51.100.10" in read_map(mp))
            check("1  source is wazuh-rule-5715", "wazuh-rule-5715" in out)

            # 2. duplicate alert is a no-op (per-claim idempotency, PT-05)
            before = read_map(mp)
            rc, out, err = run(base + ["ingest", "--render"],
                               stdin=json.dumps(envelope(alert(5715, 5, "198.51.100.10"))))
            # A repeat claim from the same source either changes nothing (same second) or
            # renews the lease (later second); both are correct, and neither re-renders the
            # map, because the map carries no expiry column.
            check("2  duplicate alert is a no-op or a renewal",
                  rc == 0 and ("unchanged" in out or "extended" in out), out.strip())
            check("2  map not rewritten", read_map(mp) == before)

            # 3. PT-09: a level alone is severity, not evidence - --confirm-by-level opts in
            rc, out, err = run(base + ["ingest", "--render", "--confirm-by-level"],
                               stdin=json.dumps(alert(5710, 13, "198.51.100.11")))
            check("3  --confirm-by-level level 13 -> confirmed (rc=%d) %s" % (rc, err.strip()), rc == 0)
            check("3  198.51.100.11 in map", "198.51.100.11" in read_map(mp))
            rc, out, _ = run(base + ["list", "--json"])
            entry = [x for x in json.loads(out) if x["ip"] == "198.51.100.11"][0]
            check("3  confirmed TTL is 259200s", entry["expires_at"] - entry["created_at"] == 259200)

            # 4. PT-09 default: a high-severity rule that is not on the confirm list is a suspect
            rc, out, err = run(base + ["ingest", "--render"],
                               stdin=json.dumps(alert(5710, 13, "198.51.100.19")))
            check("4  default level 13 -> suspect (rc=%d) %s" % (rc, err.strip()), rc == 0)
            check("4  suspect verdict recorded", "suspect" in out)
            rc, out, _ = run(base + ["list", "--json"])
            entry = [x for x in json.loads(out) if x["ip"] == "198.51.100.19"][0]
            check("4  suspect TTL is 86400s", entry["expires_at"] - entry["created_at"] == 86400)

            # 5. PT-09: a rule id on the confirm list yields confirmed without any flag
            rc, out, err = run(base + ["ingest", "--render"],
                               stdin=json.dumps(alert(120006, 8, "198.51.100.20")))
            check("5  rule 120006 -> confirmed (rc=%d) %s" % (rc, err.strip()), rc == 0)
            check("5  confirmed verdict recorded", "confirmed" in out)

            # 6. custom confirm rule id is honoured
            rc, out, err = run(base + ["ingest", "--render", "--confirm-rule", "931151"],
                               stdin=json.dumps(alert(931151, 10, "198.51.100.21")))
            check("6  --confirm-rule 931151 -> confirmed (rc=%d) %s" % (rc, err.strip()), rc == 0)
            check("6  confirmed via custom rule", "confirmed" in out)

            # 7. --verdict override wins over rule-id derivation
            rc, out, err = run(base + ["ingest", "--render", "--verdict", "confirmed", "--source", "manual"],
                               stdin=json.dumps(alert(50000, 3, "198.51.100.12")))
            check("7  --verdict override works (rc=%d) %s" % (rc, err.strip()), rc == 0)
            check("7  confirmed via override", "confirmed" in out)

            # 8. loop prevention - an alert sourced from our own tarpit log must not claim
            rc, out, err = run(base + ["ingest", "--render"],
                               stdin=json.dumps(alert(5715, 5, "198.51.100.13",
                                                      location="/var/log/httpd/tarpit-test-access.log")))
            check("8  own-log alert is skipped", "is our own" in out)
            check("8  nothing written to map", "198.51.100.13" not in read_map(mp))

            # 9. allowlist wins over the verdict
            with open(allowlist, "w") as handle:
                handle.write("# test allowlist\n198.51.100.14\n")
            rc, out, err = run(base + ["ingest", "--render"],
                               stdin=json.dumps(alert(5715, 5, "198.51.100.14")))
            check("9  allowlisted IP not claimed", "allowlist" in out and "198.51.100.14" not in read_map(mp))

            # 10. agent binding - refuse an alert about a different agent
            rc, out, err = run(base + ["ingest", "--render", "--expect-agent-id", "206434"],
                               stdin=json.dumps(alert(5715, 5, "198.51.100.15", agent_id="99999")))
            check("10 wrong agent id rejected", rc != 0 and "refusing" in err)

            # 11. data.srcip as a list (Wazuh sometimes emits a list)
            alert_obj = alert(5715, 5, "198.51.100.16")
            alert_obj["data"]["srcip"] = ["198.51.100.16", "198.51.100.17"]
            rc, out, err = run(base + ["ingest", "--render"], stdin=json.dumps(alert_obj))
            check("11 list srcip handled (rc=%d) %s" % (rc, err.strip()), rc == 0)
            check("11 first address claimed", "198.51.100.16" in read_map(mp))

            # 12. no source address at all -> clean error, not a traceback
            rc, out, err = run(base + ["ingest"], stdin=json.dumps({"rule": {"id": 1, "level": 3}}))
            check("12 missing srcip errors cleanly", rc != 0 and "no source address" in err and "Traceback" not in err)

            # 13. PT-02: a JSON array of alerts (API poller / batched fleet claim)
            batch = [alert(5715, 5, "198.51.100.30"), envelope(alert(5710, 4, "198.51.100.31"))]
            rc, out, err = run(base + ["ingest", "--render"], stdin=json.dumps(batch))
            check("13 array payload ingested (rc=%d) %s" % (rc, err.strip()), rc == 0)
            check("13 both addresses present",
                  "198.51.100.30" in read_map(mp) and "198.51.100.31" in read_map(mp))

            # 14. PT-02: pretty-printed (multi-line) payload on stdin must not hang or fail
            pretty = json.dumps(alert(5715, 5, "198.51.100.32"), indent=2)
            rc, out, err = run(base + ["ingest", "--render"], stdin=pretty)
            check("14 multi-line stdin payload (rc=%d) %s" % (rc, err.strip()), rc == 0)
            check("14 address claimed from multi-line payload", "198.51.100.32" in read_map(mp))

            # 15. PT-02: the active-response handshake is protocol chatter, never a verdict
            rc, out, err = run(base + ["ingest", "--render"],
                               stdin=json.dumps(envelope(alert(5715, 5, "198.51.100.33"), command="check_keys")))
            check("15 check_keys is not claimed", rc == 0 and "protocol" in out and "198.51.100.33" not in read_map(mp))

            # 16. PT-02: a delete/unban event must never create a new claim
            rc, out, err = run(base + ["ingest", "--render"],
                               stdin=json.dumps(envelope(alert(5715, 5, "198.51.100.34"), command="delete")))
            check("16 delete does not claim", rc == 0 and "198.51.100.34" not in read_map(mp))
            check("16 delete is reported as ignored", "ignored" in out)

            # 17. PT-02: --on-delete revoke honours the unban for the matching claim
            run(base + ["ingest", "--render", "--source", "wazuh-rule-5715"],
                stdin=json.dumps(alert(5715, 5, "198.51.100.35")))
            rc, out, err = run(base + ["ingest", "--render", "--source", "wazuh-rule-5715",
                                      "--on-delete", "revoke"],
                               stdin=json.dumps(envelope(alert(5715, 5, "198.51.100.35"), command="delete")))
            check("17 --on-delete revoke removes the claim (rc=%d) %s" % (rc, err.strip()), rc == 0)
            check("17 address gone from map", "198.51.100.35" not in read_map(mp))

            # 18. PT-05: a second source for the same address is a new claim, not a duplicate
            run(base + ["ingest", "--render", "--source", "wazuh-rule-5715"],
                stdin=json.dumps(alert(5715, 5, "198.51.100.36")))
            rc, out, err = run(base + ["ingest", "--render", "--source", "fail2ban-apache-fleet-filter"],
                               stdin=json.dumps(alert(5715, 5, "198.51.100.36")))
            check("18 second source adds a claim (rc=%d) %s" % (rc, err.strip()), rc == 0 and "added" in out)
            rc, out, _ = run(base + ["list", "--json"])
            entry = [x for x in json.loads(out) if x["ip"] == "198.51.100.36"][0]
            check("18 both claims folded into one row", entry["claims"] == 2)

            # 19. PT-05: a weaker verdict never downgrades an active confirmed claim
            run(base + ["ingest", "--render", "--verdict", "confirmed", "--source", "sig-x"],
                stdin=json.dumps(alert(120006, 8, "198.51.100.37")))
            rc, out, err = run(base + ["ingest", "--render", "--verdict", "suspect", "--source", "sig-x"],
                               stdin=json.dumps(alert(120006, 8, "198.51.100.37")))
            check("19 repeat weaker claim is unchanged", rc == 0 and "unchanged" in out)
            rc, out, _ = run(base + ["list", "--json"])
            entry = [x for x in json.loads(out) if x["ip"] == "198.51.100.37"][0]
            check("19 confirmed verdict preserved", entry["verdict"] == "confirmed")
            # 20. PT-05: suspect -> confirmed promotion adopts the confirmed TTL
            run(base + ["ingest", "--render", "--verdict", "suspect", "--source", "sig-y"],
                stdin=json.dumps(alert(5715, 5, "198.51.100.38")))
            rc, out, err = run(base + ["ingest", "--render", "--verdict", "confirmed", "--source", "sig-y"],
                               stdin=json.dumps(alert(5715, 5, "198.51.100.38")))
            check("20 promotion reported", rc == 0 and "promoted" in out)
            rc, out, _ = run(base + ["list", "--json"])
            entry = [x for x in json.loads(out) if x["ip"] == "198.51.100.38"][0]
            # created_at stays at the original suspect claim, so the promoted window can be
            # a second wider than 259200 when the two calls straddle a second boundary.
            check("20 promoted TTL is 259200s",
                  259200 <= entry["expires_at"] - entry["created_at"] <= 259201,
                  str(entry))

            # 21. PT-05: revoking one claim leaves the other sources' claims intact
            run(base + ["ingest", "--render", "--source", "wazuh-rule-5715"],
                stdin=json.dumps(alert(5715, 5, "198.51.100.39")))
            run(base + ["ingest", "--render", "--source", "fail2ban-apache-fleet-filter"],
                stdin=json.dumps(alert(5715, 5, "198.51.100.39")))
            rc, out, err = run(base + ["revoke", "198.51.100.39", "--claim-key", "wazuh-rule-5715", "--render"])
            check("21 single-claim revoke (rc=%d) %s" % (rc, err.strip()), rc == 0 and "claim wazuh-rule-5715" in out)
            rc, out, _ = run(base + ["list", "--json"])
            entry = [x for x in json.loads(out) if x["ip"] == "198.51.100.39"][0]
            check("21 other claim survives", entry["claims"] == 1 and entry["source"] == "fail2ban-apache-fleet-filter")

            # 22. PT-05: a v1 (single-row) store migrates instead of erroring
            v1dir = os.path.join(work, "v1-" + os.path.basename(python))
            os.makedirs(v1dir)
            v1db = os.path.join(v1dir, "state.db")
            conn = sqlite3.connect(v1db)
            conn.execute("CREATE TABLE leases (ip TEXT PRIMARY KEY, verdict TEXT NOT NULL, source TEXT,"
                         " author TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)")
            conn.execute("INSERT INTO leases VALUES ('198.51.100.40','confirmed','wazuh-rule-5715','lab-web01',"
                         "strftime('%s','now'),strftime('%s','now')+600)")
            conn.commit()
            conn.close()
            rc, out, err = run(["--db", v1db, "--map", os.path.join(v1dir, "m.map"),
                                "--allowlist", allowlist, "list"])
            check("22 v1 store lists (rc=%d) %s" % (rc, err.strip()), rc == 0 and "198.51.100.40" in out)
            rc, out, err = run(["--db", v1db, "--map", os.path.join(v1dir, "m.map"),
                                "--allowlist", allowlist, "claim", "198.51.100.41",
                                "--verdict", "suspect", "--source", "cli", "--render"])
            check("22 v1 store migrates on first write", rc == 0 and "migrated v1 store" in err)
            tables = [row[0] for row in sqlite3.connect(v1db).execute(
                "SELECT name FROM sqlite_master WHERE type='table'")]
            check("22 v1 table preserved as backup", "leases_v1_backup" in tables and "claims" in tables)

            # 23. PT-01: expiring the last lease renders an empty map without --allow-empty
            short = os.path.join(work, "short.db")
            short_map = os.path.join(work, "short.map")
            rc, out, err = run(["--db", short, "--map", short_map, "--allowlist", allowlist,
                                "claim", "198.51.100.42", "--verdict", "suspect", "--source", "cli",
                                "--ttl", "1", "--render"])
            check("23 short lease rendered (rc=%d) %s" % (rc, err.strip()), rc == 0)
            check("23 map has the entry", "198.51.100.42" in read_map(short_map))
            conn = sqlite3.connect(short)
            conn.execute("UPDATE claims SET expires_at = strftime('%s','now') - 1")
            conn.commit()
            conn.close()
            rc, out, err = run(["--db", short, "--map", short_map, "--allowlist", allowlist,
                                "expire", "--render"])
            check("24 expire renders empty map (rc=%d) %s" % (rc, err.strip()), rc == 0)
            check("24 entry removed from map", "198.51.100.42" not in read_map(short_map))
            check("24 map file still exists", os.path.exists(short_map))

            # 25. PT-01: an unreadable store still refuses to blank an existing map
            corrupt = os.path.join(work, "corrupt.db")
            with open(corrupt, "w") as handle:
                handle.write("this is not a sqlite database\n")
            guarded = os.path.join(work, "guarded.map")
            with open(guarded, "w") as handle:
                handle.write("# Generated by adaptive-tarpit at now - do not edit by hand.\n198.51.100.99 1\n")
            rc, out, err = run(["--db", corrupt, "--map", guarded, "--allowlist", allowlist,
                                "render", "--allow-empty"])
            check("25 unreadable store refuses to blank the map", rc != 0 and "cannot open" in err)
            check("25 map untouched", "198.51.100.99" in read_map(guarded))

            # 26. PT-04: the quota cap is honoured by claim/revoke/expire, not just ingest
            capped = os.path.join(work, "capped.db")
            capped_map = os.path.join(work, "capped.map")
            run(["--db", capped, "--map", capped_map, "--allowlist", allowlist, "claim",
                 "198.51.100.43", "--verdict", "suspect", "--source", "cli", "--render"])
            rc, out, err = run(["--db", capped, "--map", capped_map, "--allowlist", allowlist, "claim",
                                "198.51.100.44", "--verdict", "suspect", "--source", "cli",
                                "--render", "--max-tarpit", "1"])
            check("26 claim honours --max-tarpit (rc=%d) %s" % (rc, err.strip()), rc == 0)
            body = read_map(capped_map)
            rendered = dict(ln.split() for ln in body.splitlines() if ln and not ln.startswith("#"))
            check("26 both addresses present", set(rendered) == {"198.51.100.43", "198.51.100.44"})
            check("26 exactly one address holds value 1", sorted(rendered.values()).count("1") == 1,
                  str(rendered))
            check("26 the other address is over quota (value 2)",
                  sorted(rendered.values()).count("2") == 1, str(rendered))

            # 27. PT-04: allowlisted addresses render as 0 instead of disappearing
            with open(allowlist, "w") as handle:
                handle.write("198.51.100.43\n")
            body = run(["--db", capped, "--map", capped_map, "--allowlist", allowlist,
                        "render", "--dry-run"])[1]
            check("27 allowlisted lease renders as 0", "198.51.100.43 0" in body)
            with open(allowlist, "w") as handle:
                handle.write("")

            # 28. PT-11: verify agrees with a correct map, and catches drift
            rc, out, err = run(["--db", capped, "--map", capped_map, "--allowlist", allowlist, "verify"])
            check("28 verify passes on a correct map (rc=%d) %s" % (rc, err.strip()), rc == 0 and "ok:" in out)
            with open(capped_map, "w") as handle:
                handle.write("# Generated by adaptive-tarpit at now - do not edit by hand.\n198.51.100.43 1\n")
            rc, out, err = run(["--db", capped, "--map", capped_map, "--allowlist", allowlist, "verify"])
            check("28 verify detects drift", rc != 0 and "drifted" in err)
            with open(capped_map, "w") as handle:
                handle.write("hand written\n")
            rc, out, err = run(["--db", capped, "--map", capped_map, "--allowlist", allowlist, "verify"])
            check("28 verify rejects a hand-edited map", rc != 0 and "not a generated artifact" in err)
            os.unlink(capped_map)
            rc, out, err = run(["--db", capped, "--map", capped_map, "--allowlist", allowlist, "verify"])
            check("28 verify detects a missing map", rc != 0 and "missing" in err)

            # 29. legacy: --file and --dry-run still work
            payload = os.path.join(work, "alert.json")
            with open(payload, "w") as handle:
                handle.write(json.dumps(alert(5715, 5, "198.51.100.60")))
            before = read_map(mp)
            rc, out, err = run(base + ["ingest", "--file", payload, "--render", "--dry-run"])
            check("29 --file --dry-run works (rc=%d) %s" % (rc, err.strip()), rc == 0 and "would claim" in out)
            check("29 dry-run did not write", read_map(mp) == before)

            # 30. invalid JSON -> clean error
            rc, out, err = run(base + ["ingest"], stdin="not json at all")
            check("30 invalid JSON errors cleanly", rc != 0 and "not valid JSON" in err)

            # 31. the active-response shim still produces a claimable payload (end to end)
            ar = os.path.join(ROOT, "detector", "wazuh", "active-response", "fleet-filter.sh")
            if os.path.exists(ar):
                env = dict(os.environ, ADAPTIVE_TARPIT_BIN=CONTROLLER,
                           ADAPTIVE_TARPIT_DB=db, ADAPTIVE_TARPIT_MAP=mp,
                           ADAPTIVE_TARPIT_ALLOWLIST=allowlist)
                proc = subprocess.run([ar], input=json.dumps(alert(5715, 5, "198.51.100.61")),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      universal_newlines=True, env=env)
                check("31 AR shim -> controller (rc=%d) %s" % (proc.returncode, proc.stderr.strip()),
                      proc.returncode == 0)
                check("31 AR shim claimed the address", "198.51.100.61" in read_map(mp))

                # 32. the shim also accepts the 4.x envelope (PT-02 end to end)
                proc = subprocess.run([ar], input=json.dumps(envelope(alert(5715, 5, "198.51.100.62"))),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      universal_newlines=True, env=env)
                check("32 AR shim accepts a 4.x envelope (rc=%d) %s" % (proc.returncode, proc.stderr.strip()),
                      proc.returncode == 0 and "198.51.100.62" in read_map(mp))

                # 33. the shim must not hang on an open pipe that only sends the handshake
                proc = subprocess.run([ar], input=json.dumps(envelope(alert(5715, 5, "198.51.100.63"),
                                                                      command="check_keys")),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      universal_newlines=True, env=env, timeout=20)
                check("33 AR handshake reply does not hang (rc=%d)" % proc.returncode,
                      proc.returncode == 0 and "198.51.100.63" not in read_map(mp))
            else:
                print("  skip 31-33 (no active-response shim present)")

            # 34. the fail2ban shim output is accepted by the same ingest path
            shim = os.path.join(ROOT, "detector", "fail2ban", "f2b-fleet-filter")
            if os.path.exists(shim):
                env = dict(os.environ, ADAPTIVE_TARPIT_BIN=CONTROLLER,
                           ADAPTIVE_TARPIT_DB=db, ADAPTIVE_TARPIT_MAP=mp,
                           ADAPTIVE_TARPIT_ALLOWLIST=allowlist)
                proc = subprocess.run([shim, "apache-fleet-filter", "198.51.100.70"],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      universal_newlines=True, env=env)
                check("34 fail2ban shim -> controller (rc=%d) %s" % (proc.returncode, proc.stderr.strip()),
                      proc.returncode == 0)
                rc, out, _ = run(base + ["list", "--json"])
                entry = [x for x in json.loads(out) if x["ip"] == "198.51.100.70"][0]
                check("34 source is the jail", entry["source"] == "fail2ban-apache-fleet-filter")
                check("34 author is fail2ban", entry["author"] == "fail2ban")
                check("34 verdict is suspect", entry["verdict"] == "suspect")
            else:
                print("  skip 34 (no fail2ban shim present)")

            # 35. the map is still parseable by Apache's txt: reader
            body = read_map(mp)
            bad = [ln for ln in body.splitlines() if ln and not ln.startswith("#") and len(ln.split()) != 2]
            check("35 map lines are all 'ip value'", not bad, str(bad[:3]))

        print("\n%s checks: %d passed, %d failed" % ("PASS" if FAIL == 0 else "FAIL", PASS, FAIL))
        return 1 if FAIL else 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
