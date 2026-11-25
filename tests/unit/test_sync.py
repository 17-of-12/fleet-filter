#!/usr/bin/env python3
"""Tests for the console syncer in web/sync.py.

The console renders whatever this module stores, so the properties under test are the ones the UI
depends on: every address a controller event names must reach the cache, `ts` must land on one
comparable clock across hosts, and a malformed line must be skipped rather than abort the sync.

The address rule is the reason this file exists. The controller writes `claim`/`revoke` records with
a single `ip`, but `expire` records with an `addresses` list plus a `removed` count - one line per
sweep, not per address. The first version of the syncer read only `ip`, so every expiry landed as a
blank-address row and a three-address sweep showed up as one anonymous event.

Runs under Python 3.9 and 3.12; needs no third-party modules.
"""

from __future__ import print_function

import importlib.util
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

SPEC = importlib.util.spec_from_file_location("pt_sync", os.path.join(ROOT, "web", "sync.py"))
pt_sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pt_sync)

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


def line(**fields):
    """Serialise one audit record the way the controller writes it (sorted keys, compact)."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


# --- audit_timestamp -------------------------------------------------------------------------------
check(pt_sync.audit_timestamp("2026-11-15T14:20:22Z") == 1794752422,
      "ISO-8601 UTC ts normalises to the right unix integer")
check(pt_sync.audit_timestamp(1794752422) == 1794752422, "an integer ts passes through unchanged")
check(pt_sync.audit_timestamp("not-a-date") == 0, "an unparseable ts becomes 0 rather than raising")
check(pt_sync.audit_timestamp(None) == 0, "a missing ts becomes 0 rather than raising")

# --- audit_addresses: the two controller record shapes ------------------------------------------
claim = {"schema": 1, "event": "claim", "host": "lab-web01.lab", "ip": "198.51.100.128",
         "verdict": "confirmed", "source": "CVE-2026-119618/probe_path", "result": "ok",
         "ts": "2026-11-15T01:57:39Z"}
check(pt_sync.audit_addresses(claim) == ["198.51.100.128"], "a claim record yields its single ip")

# verbatim shape of a live expire line from lab-web01's audit.jsonl
expire = {"schema": 1, "event": "expire", "host": "lab-web01.lab", "removed": 3,
          "addresses": ["198.51.100.61", "198.51.100.70", "198.51.100.71"],
          "ts": "2026-11-15T14:20:22Z"}
check(pt_sync.audit_addresses(expire) == ["198.51.100.61", "198.51.100.70", "198.51.100.71"],
      "an expire record yields every address in `addresses` (the regression this file was written for)")
check(pt_sync.audit_addresses({"event": "bypass", "state": "on"}) == [""],
      "a record naming no address still yields one event with an empty address")
check(pt_sync.audit_addresses({"event": "expire", "addresses": ["10.0.0.1", "", None, " "]}) == ["10.0.0.1"],
      "blank and non-string entries are filtered out of an addresses list")
check(pt_sync.audit_addresses({"event": "expire", "addresses": "10.0.0.2"}) == ["10.0.0.2"],
      "an addresses value that is a bare string is still honoured")

# --- parse_audit_lines ---------------------------------------------------------------------------
payload = "\n".join([
    line(**claim),
    line(**expire),
    "this is not json at all",
    '"a bare json string, not an object"',
    "",
    "   ",
]).encode("utf-8")

events = pt_sync.parse_audit_lines(payload)
check(len(events) == 4, "one claim + one 3-address expire = 4 events (malformed lines skipped)")
check(all(isinstance(e, dict) for e in events), "every event is a dict")
check(sorted(e["ip"] for e in events) == sorted(
    ["198.51.100.128", "198.51.100.61", "198.51.100.70", "198.51.100.71"]),
    "no event loses its address, whichever field the controller put it in")
check(all(e["ts"] > 0 for e in events), "every event carries a usable timestamp")

by_ip = dict((e["ip"], e) for e in events)
check(by_ip["198.51.100.128"]["action"] == "claim"
      and by_ip["198.51.100.128"]["verdict"] == "confirmed"
      and by_ip["198.51.100.128"]["source"] == "CVE-2026-119618/probe_path",
      "event/verdict/source map onto action/verdict/source for a claim")
check(all(by_ip[ip]["action"] == "expire" for ip in ("198.51.100.61", "198.51.100.70", "198.51.100.71")),
      "each expanded address of an expire sweep carries the expire action")
check(all(by_ip[ip]["host"] == "lab-web01.lab" for ip in by_ip),
      "the record's own host is carried onto every expanded event")

# empty and whitespace-only payloads must not raise
check(pt_sync.parse_audit_lines(b"") == [], "an empty payload parses to no events")
check(pt_sync.parse_audit_lines(b"\n\n") == [], "a whitespace-only payload parses to no events")

# --- cache publication: the scratch database is renamed, never copied across a mount ---------------


class _TempfileRecorder(object):
    """Wrap the real tempfile module and record the directory each temp file was asked for.

    `build_cache` promises the scratch database lands next to the cache it becomes, because
    os.replace cannot rename across a mount. Asserting on the recorded `dir=` is the only way to test
    that promise on a host where /tmp and the cache happen to share a filesystem - and the missing
    `dir=` is exactly what made the deployed timer fail with EXDEV on its first run.
    """

    def __init__(self):
        """Start with an empty record of the directories temp files were requested in."""
        self.dirs = []

    def NamedTemporaryFile(self, **kwargs):
        """Create the file for real, remembering where it was put."""
        handle = tempfile.NamedTemporaryFile(**kwargs)
        self.dirs.append(os.path.dirname(handle.name))
        return handle


work = tempfile.mkdtemp(prefix="pt-sync-cache-")
try:
    nested = os.path.join(work, "nested")
    os.makedirs(nested)
    registry_path = os.path.join(nested, "installs.yaml")
    with open(registry_path, "w") as handle:
        handle.write("installs:\n  - fqdn: host.example.edu\n    state_db: ''\n    audit_log: ''\n")
    cache_path = os.path.join(nested, "cache.db")
    recorder = _TempfileRecorder()
    real_tempfile = pt_sync.tempfile
    try:
        pt_sync.tempfile = recorder
        pt_sync.build_cache(cache_path, registry_path)
    finally:
        pt_sync.tempfile = real_tempfile
    check(recorder.dirs == [nested],
          "the scratch database is created beside the cache, so publishing cannot hit EXDEV")
    check(os.path.isfile(cache_path), "the cache exists at the requested path after the swap")
    check(sorted(os.listdir(nested)) == ["cache.db", "installs.yaml"],
          "no scratch database is left behind, so repeated runs cannot pile up files")
finally:
    shutil.rmtree(work, ignore_errors=True)

# --- ssh_read_raw: a hung ssh must be killed, not abandoned ------------------------------------------
# `communicate(timeout=...)` raises TimeoutExpired but leaves the child running, so the old version
# accumulated one live ssh per unreachable host per sync. The process factory is injectable for
# exactly this: the timeout path cannot be reached with a real ssh target on every interpreter.
class _FakePopen(object):
    """A Popen stand-in that can answer, time out, or fail without needing an SSH target."""

    def __init__(self, behaviour="ok", payload=b"", error=b"", exit_code=0):
        """Record what the fake will do when the syncer drives it."""
        self.behaviour = behaviour
        self.payload = payload
        self.error = error
        self.returncode = exit_code
        self.killed = False
        self.stdout = None
        self.stderr = None
        self.calls = 0

    def __call__(self, cmd, stdout=None, stderr=None):
        """Act as subprocess.Popen(...) and hand back the configured behaviour."""
        self.calls += 1
        return self

    def __enter__(self):
        """Enter the context manager the syncer uses so the pipes are always closed."""
        return self

    def __exit__(self, *exc):
        """Leave the context manager; the fake holds no real descriptors to close."""
        return False

    def communicate(self, timeout=None):
        """Raise TimeoutExpired once for a hung ssh, then answer as a killed child would."""
        if self.behaviour == "timeout" and not self.killed:
            raise subprocess.TimeoutExpired(["ssh"], timeout)
        return self.payload, self.error

    def kill(self):
        """Mark the child killed so the test can assert it was reaped."""
        self.killed = True


ok_proc = _FakePopen(payload=b"payload")
check(pt_sync.ssh_read_raw("h.example", "cat x", popen=ok_proc) == b"payload",
      "a successful read returns the stdout bytes")
check(ok_proc.calls == 1, "the ssh command is invoked exactly once per read")

timeout_proc = _FakePopen(behaviour="timeout")
try:
    pt_sync.ssh_read_raw("h.example", "cat x", timeout=5, popen=timeout_proc)
    raised = False
except IOError as exc:
    raised = "timed out after 5s" in str(exc)
check(raised, "a timed-out ssh raises IOError naming the host and the timeout")
check(timeout_proc.killed, "the timed-out ssh process is killed instead of being abandoned")

failing_proc = _FakePopen(error=b"Permission denied", exit_code=255)
try:
    pt_sync.ssh_read_raw("h.example", "cat x", popen=failing_proc)
    raised = False
except IOError as exc:
    raised = "Permission denied" in str(exc)
check(raised, "a non-zero ssh exit surfaces stderr as the per-host error the cache records")

# --- container inventory: what the sync stores, and what a failed probe must not destroy -------------
# The owner asked for container versions to be "kept listed" in the console. The interesting failure
# is not the missing row, it is the row that disappears when a probe fails: an SSH timeout used to
# read as "this host has no containers", which is a different fact. Both halves are asserted here.
CONTAINER_INVENTORY = {
    "schema_version": 1,
    "generated_at": 1700000000,
    "hosts": [{
        "fqdn": "lab-web01.lab",
        "source": "ssh",
        "runtimes": [{"name": "podman", "version": "4.9.4"}],
        "containers": [{"runtime": "podman", "name": "fleet-filter-apache-lab-web01",
                        "image": "localhost/fleet-filter-apache:0.1.0", "state": "running",
                        "status": "Up 3 days", "container_id": "74abd0194d7e", "pod": ""}],
        "images": [{"image_id": "sha256:88b8bed0",
                    "repo_tags": ["localhost/fleet-filter-apache:0.1.0"],
                    "digest": "sha256:88b8bed0", "size": "263", "fleet_filter_owned": True}],
        "storage": {"podman": [{"Type": "local", "Count": 6, "Size": 3435134976,
                                "Reclaimable": 3435134976}]},
    }],
}

work = tempfile.mkdtemp(prefix="pt-sync-cont-")
try:
    registry_path = os.path.join(work, "installs.yaml")
    with open(registry_path, "w") as handle:
        handle.write("installs:\n  - fqdn: lab-web01.lab\n    stage: gateway\n")
    cache_path = os.path.join(work, "cache.db")
    pt_sync.build_cache(cache_path, registry_path, container_inventory=CONTAINER_INVENTORY)
    conn = sqlite3.connect(cache_path)
    conn.row_factory = sqlite3.Row
    containers = [dict(r) for r in conn.execute("SELECT * FROM containers").fetchall()]
    first_status = dict(conn.execute("SELECT * FROM container_hosts").fetchone())
    runtimes = [dict(r) for r in conn.execute("SELECT * FROM container_runtimes").fetchall()]
    images = [dict(r) for r in conn.execute("SELECT * FROM container_images").fetchall()]
    storage = [dict(r) for r in conn.execute("SELECT * FROM container_storage").fetchall()]
    conn.close()
    check(containers == [{"host": "lab-web01.lab", "runtime": "podman",
                          "name": "fleet-filter-apache-lab-web01",
                          "image": "localhost/fleet-filter-apache:0.1.0", "state": "running",
                          "status": "Up 3 days", "container_id": "74abd0194d7e", "pod": ""}],
          "the container row from the inventory is stored verbatim")
    check(runtimes == [{"host": "lab-web01.lab", "runtime": "podman",
                        "version": "4.9.4"}], "the runtime version is recorded")
    check(len(images) == 1 and images[0]["fleet_filter_owned"] == 1
          and images[0]["digest"] == "sha256:88b8bed0",
          "image tags, digest, and project ownership are recorded")
    check(len(storage) == 1 and json.loads(storage[0]["rows_json"])[0]["Count"] == 6,
          "system df rows are kept per runtime")

    # Now the same host with a failed probe and no data: the rows must survive, the error must appear.
    failed = {"schema_version": 1, "generated_at": 1700000600, "hosts": [
        {"fqdn": "lab-web01.lab", "source": "ssh", "ssh_error": "ssh timed out",
         "runtimes": [], "containers": [], "images": [], "storage": {}}]}
    stats = pt_sync.build_cache(cache_path, registry_path, container_inventory=failed)
    conn = sqlite3.connect(cache_path)
    conn.row_factory = sqlite3.Row
    kept = [dict(r) for r in conn.execute("SELECT * FROM containers").fetchall()]
    status = dict(conn.execute("SELECT * FROM container_hosts").fetchone())
    conn.close()
    check(kept == containers, "a failed probe keeps the last good container rows instead of wiping them")
    check(status["error"] == "ssh timed out", "the probe failure is recorded on the host row")
    check(status["synced_at"] == first_status["synced_at"],
          "the timestamp still points at the last successful look, so age is honest about the data")
    check(any("containers: ssh timed out" in e for e in stats["errors"]),
          "the sync report surfaces the container probe failure alongside the others")

    # A host whose inventory has data AND an error keeps the data path (partial reads are real).
    partial = {"schema_version": 1, "generated_at": 1700001200, "hosts": [
        {"fqdn": "lab-web01.lab", "source": "ssh", "ssh_error": "ssh exited 1",
         "runtimes": [{"name": "podman", "version": "4.9.4"}], "containers": [], "images": [],
         "storage": {}}]}
    pt_sync.build_cache(cache_path, registry_path, container_inventory=partial)
    conn = sqlite3.connect(cache_path)
    emptied = conn.execute("SELECT COUNT(*) FROM containers").fetchone()[0]
    conn.close()
    check(emptied == 0,
          "a probe that returned data (empty container list) replaces the rows rather than keeping stale ones")
finally:
    shutil.rmtree(work, ignore_errors=True)

# --- webtree audit (Bundle Z, Z6): the report the host wrote, and what a bad fetch must preserve -----
# The console renders the report `bin/webtree-audit.py` leaves on the host it audited. Two properties
# matter: clean files are NOT copied (a docroot of 3,879 clean files is a finding list only if you
# print it), and an unreadable report keeps the previous findings instead of silently reporting an
# empty webtree - the same rule PTN-10 set for every other table in this cache.
REPORT = {
    "generated_at": "2026-11-16T00:00:00Z", "root": "/var/www/html", "mode": "full",
    "files_audited": 4, "new_files": 4, "changed_files": 0, "reused_files": 0,
    "removed_files": 0, "files_total": 4,
    "summary": {"clean": 2, "review": 1, "quarantine": 1, "removed": 0, "errors": 0},
    "files": [
        {"path": "/var/www/html/index.html", "verdict": "clean", "score": 1, "size": 900,
         "mtime": 1700000000, "reasons": []},
        {"path": "/var/www/html/ok.css", "verdict": "clean", "score": 0, "size": 120,
         "mtime": 1700000000, "reasons": []},
        {"path": "/var/www/html/x.js", "verdict": "review", "score": 8, "size": 2048,
         "mtime": 1700000000, "reasons": ["minified: 91 bytes/line"], "yara": []},
        {"path": "/var/www/html/upload.php", "verdict": "quarantine", "score": 17, "size": 4310,
         "mtime": 1700000000, "reasons": ["eval", "base64_decode"],
         "yara": ["PHP_Sink_On_Superglobal"]},
    ],
}

work = tempfile.mkdtemp(prefix="pt-sync-webtree-")
try:
    hostname = socket.gethostname()          # the local-host path, so the test needs no SSH target
    report_path = os.path.join(work, "webtree-report.json")
    with open(report_path, "w") as handle:
        json.dump(REPORT, handle)
    registry_path = os.path.join(work, "installs.yaml")
    with open(registry_path, "w") as handle:
        handle.write("installs:\n  - fqdn: %s\n    stage: control\n    webtree_report: %s\n"
                     % (hostname, report_path))
    cache_path = os.path.join(work, "cache.db")
    stats = pt_sync.build_cache(cache_path, registry_path, container_inventory={"hosts": []})
    conn = sqlite3.connect(cache_path)
    conn.row_factory = sqlite3.Row
    audits = [dict(r) for r in conn.execute("SELECT * FROM webtree_audits").fetchall()]
    files = [dict(r) for r in conn.execute("SELECT host, path, verdict, score FROM webtree_files"
                                           " ORDER BY score DESC").fetchall()]
    conn.close()
    check(stats["webtree_findings"] == 2, "only non-clean files are stored: 2 findings, not 4 records")
    check(len(audits) == 1 and audits[0]["files_total"] == 4 and audits[0]["quarantine"] == 1
          and audits[0]["docroot"] == "/var/www/html" and audits[0]["mode"] == "full",
          "the audit summary row carries the report's own counts, root, and mode")
    check([f["path"].rsplit("/", 1)[1] for f in files] == ["upload.php", "x.js"],
          "flagged files are stored and ordered by score, highest first")
    check(pt_sync.report_generated_at(REPORT) > 0
          and pt_sync.report_generated_at({"generated_at": "not-a-date"}) == 0,
          "the report timestamp parses, and a malformed one degrades to 0 instead of raising")
    check(pt_sync._as_int("12") == 12 and pt_sync._as_int(None) == 0 and pt_sync._as_int("x") == 0,
          "a malformed numeric field costs 0 rather than the whole row")

    # The report goes missing (path moved, host rebuilt): the previous findings must survive the swap.
    missing_registry = os.path.join(work, "installs-missing.yaml")
    with open(missing_registry, "w") as handle:
        handle.write("installs:\n  - fqdn: %s\n    stage: control\n    webtree_report: %s\n"
                     % (hostname, os.path.join(work, "gone.json")))
    stats = pt_sync.build_cache(cache_path, missing_registry, container_inventory={"hosts": []})
    conn = sqlite3.connect(cache_path)
    kept = conn.execute("SELECT COUNT(*) FROM webtree_files").fetchone()[0]
    audit_rows = conn.execute("SELECT COUNT(*) FROM webtree_audits").fetchone()[0]
    conn.close()
    check(kept == 2 and audit_rows == 1,
          "an unreadable report keeps the last good findings instead of reporting nothing")
    check(any("webtree report:" in e for e in stats["errors"]),
          "the unreadable report is reported per host, not swallowed")
finally:
    shutil.rmtree(work, ignore_errors=True)


# --- PTN-10: a failed state fetch keeps the last known claims instead of clearing them ---------------
# The cache is rebuilt from scratch, so a host whose state.db cannot be read used to end up with an
# `installs` row that reported an error and zero claims. For the container and webtree data the rule
# is already "keep the last good rows and say why they are old"; this applies the same rule to the
# controller's own state, where an empty claim table reads as a cleared quarantine.
work = tempfile.mkdtemp(prefix="pt-sync-state-")
try:
    host = socket.gethostname()  # the local read path, so the test never opens an SSH session
    state_db = os.path.join(work, "state.db")
    seed = sqlite3.connect(state_db)
    seed.execute("CREATE TABLE claims (ip TEXT, claim_key TEXT, verdict TEXT, source TEXT,"
                 " author TEXT, created_at INTEGER, expires_at INTEGER)")
    seed.execute("INSERT INTO claims VALUES ('198.51.100.128', 'signature:probe_path',"
                 " 'confirmed', 'fleet-filter-gateway', 'lab-web01', 1794752422, 1794838822)")
    seed.commit()
    seed.close()
    registry_path = os.path.join(work, "installs.yaml")
    with open(registry_path, "w") as handle:
        handle.write("installs:\n  - fqdn: %s\n    stage: gateway\n    state_db: %s\n"
                     % (host, state_db))
    cache_path = os.path.join(work, "cache.db")
    pt_sync.build_cache(cache_path, registry_path, container_inventory={"hosts": []})
    conn = sqlite3.connect(cache_path)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT ip, verdict FROM claims").fetchall()]
    conn.close()
    check(rows == [{"ip": "198.51.100.128", "verdict": "confirmed"}],
          "a readable state.db lands its claims in the cache")

    # Break the source: the file still exists but is no longer a database.
    with open(state_db, "wb") as handle:
        handle.write(b"not a database")
    stats = pt_sync.build_cache(cache_path, registry_path, container_inventory={"hosts": []})
    conn = sqlite3.connect(cache_path)
    conn.row_factory = sqlite3.Row
    kept = [dict(r) for r in conn.execute("SELECT ip, verdict FROM claims").fetchall()]
    install = dict(conn.execute("SELECT * FROM installs").fetchone())
    conn.close()
    check(kept == rows, "a failed state read keeps the previous claims instead of clearing them")
    check(install["sync_error"].startswith("state.db:"),
          "the host row still records why the read failed")
    check(any("state.db" in e for e in stats["errors"]),
          "the sync summary reports the failure alongside the carried rows")
finally:
    shutil.rmtree(work, ignore_errors=True)

# --- Z7: the quarantine journal is ingested, and a restored file stops counting as held -------------
# The audit says what is suspicious; the journal says what was moved. Sync has to keep both, and
# resolve a source's current state from its latest action rather than counting rows.
work = tempfile.mkdtemp(prefix="pt-sync-quarantine-")
try:
    hostname = socket.gethostname()
    docroot = os.path.join(work, "www")
    os.makedirs(docroot)
    with open(os.path.join(docroot, "index.php"), "w") as handle:
        handle.write("<?php echo 1; ?>")
    report_path = os.path.join(work, "webtree-report.json")
    with open(report_path, "w") as handle:
        json.dump({"generated_at": "2026-11-16T12:00:00Z", "root": docroot, "mode": "full",
                   "summary": {"clean": 1, "review": 0, "quarantine": 1, "removed": 0,
                               "errors": 0},
                   "files": [{"path": os.path.join(docroot, "index.php"), "verdict": "quarantine",
                              "score": 9, "size": 14, "mtime": 1700000000, "reasons": ["eval"],
                              "yara": []}]}, handle)

    journal_path = os.path.join(work, "quarantine.json")
    with open(journal_path, "w") as handle:
        json.dump({"version": 1, "entries": [
            {"action": "quarantined", "source": os.path.join(docroot, "index.php"),
             "held_at": os.path.join(work, "holding", "index.php"), "sha256": "a" * 64,
             "at": 1794856000, "verdict": "quarantine", "score": 9},
            {"action": "quarantined", "source": os.path.join(docroot, "gone.php"),
             "held_at": os.path.join(work, "holding", "gone.php"), "sha256": "b" * 64,
             "at": 1794856100, "verdict": "quarantine", "score": 11},
            {"action": "restored", "source": os.path.join(docroot, "gone.php"),
             "sha256": "b" * 64, "at": 1794856200,
             "restored_from": os.path.join(work, "holding", "gone.php")}]}, handle)

    registry_path = os.path.join(work, "installs.yaml")
    with open(registry_path, "w") as handle:
        handle.write("installs:\n  - fqdn: %s\n    stage: control\n    webtree_report: %s\n"
                     "    quarantine_journal: %s\n" % (hostname, report_path, journal_path))
    cache_path = os.path.join(work, "cache.db")
    stats = pt_sync.build_cache(cache_path, registry_path, container_inventory={"hosts": []})
    conn = sqlite3.connect(cache_path)
    conn.row_factory = sqlite3.Row
    entries = [dict(r) for r in conn.execute(
        "SELECT source, action FROM webtree_quarantine ORDER BY source").fetchall()]
    conn.close()
    check(not any("quarantine journal:" in e for e in stats["errors"]),
          "a readable journal produces no error")
    check(len(entries) == 3,
          "every journal entry is stored, including the restore: %s" % (entries,))

    # A registry that names no journal is the normal state and must not look like a failure.
    plain_registry = os.path.join(work, "plain.yaml")
    with open(plain_registry, "w") as handle:
        handle.write("installs:\n  - fqdn: %s\n    stage: control\n    webtree_report: %s\n"
                     % (hostname, report_path))
    stats = pt_sync.build_cache(os.path.join(work, "cache2.db"), plain_registry,
                                container_inventory={"hosts": []})
    check(not any("quarantine journal:" in e for e in stats["errors"]),
          "no journal configured is not reported as an error")

    # A journal path that exists but is not JSON is reported, and the rows are left alone.
    broken = os.path.join(work, "broken.json")
    with open(broken, "w") as handle:
        handle.write("not json")
    broken_registry = os.path.join(work, "broken.yaml")
    with open(broken_registry, "w") as handle:
        handle.write("installs:\n  - fqdn: %s\n    stage: control\n    webtree_report: %s\n"
                     "    quarantine_journal: %s\n" % (hostname, report_path, broken))
    stats = pt_sync.build_cache(os.path.join(work, "cache3.db"), broken_registry,
                                container_inventory={"hosts": []})
    check(any("quarantine journal:" in e for e in stats["errors"]),
          "an unparseable journal is reported per host")
finally:
    shutil.rmtree(work, ignore_errors=True)

print("test_sync.py: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
