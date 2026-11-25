#!/usr/bin/env python3
"""Collect every registered install's controller state into the console's cache.

Purpose
-------
The console renders one database, `cache.db`, instead of querying each host at page-load time.
That choice is what keeps the UI fast and keeps a down host from taking the whole page with it:
sync collects what it can, records what it could not, and the console shows the age of every
number rather than presenting stale data as current.

What it collects
----------------
* `claims` from each host's `/var/lib/adaptive-tarpit/state.db` (the durable verdict records).
* `audit_events` from each host's `/var/log/adaptive-tarpit/audit.jsonl` (the E13 event stream).
* `container_*` from `bin/container-inventory.py` - the container runtime version, every container,
  every image tag and digest, and `system df` storage per runtime, so the console can answer "what
  version is that host actually running" without an SSH session (owner ask, 2026-11-16).
* The install registry itself, so the installs page and the sync status share one source.

Safety
------
Read-only against every remote host: one `ssh cat` per file, no remote commands that write. The
local cache is rebuilt in a temp file *beside the target* and `os.replace`d, so a sync interrupted
halfway cannot leave the console serving a half-written database - and beside the target rather than
in /tmp because `os.replace` cannot rename across a mount, which is what breaks it under a unit with
`PrivateTmp=yes`.
"""

import argparse
import calendar
import datetime
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_REGISTRY = os.path.join(REPO_ROOT, "web", "installs.yaml")
DEFAULT_CACHE = "/var/lib/fleet-filter-ui/cache.db"
SCHEMA_VERSION = "1"
AUDIT_TAIL = 5000
INVENTORY_TIMEOUT = 600

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS installs (
    fqdn TEXT PRIMARY KEY, stage TEXT, deployed_at TEXT, ssh_user TEXT,
    state_db TEXT, audit_log TEXT, webtree_report TEXT, artifact_sha TEXT, notes TEXT,
    last_sync INTEGER, sync_error TEXT, gateway_policy_mode TEXT
);
CREATE TABLE IF NOT EXISTS claims (
    host TEXT, ip TEXT, claim_key TEXT, verdict TEXT, source TEXT, author TEXT,
    created_at INTEGER, expires_at INTEGER, PRIMARY KEY (host, ip, claim_key)
);
CREATE TABLE IF NOT EXISTS audit_events (
    host TEXT, ts INTEGER, ip TEXT, action TEXT, verdict TEXT, source TEXT, result TEXT,
    PRIMARY KEY (host, ts, ip, action, verdict, source, result)
);
-- Container state (owner ask 2026-11-16: "keep container versions listed and the like"). One row per
-- host records the probe outcome even when the probe failed, which is what lets the console say
-- "last good data from 3 h ago, host unreachable" instead of silently dropping the host from the page.
CREATE TABLE IF NOT EXISTS container_hosts (
    host TEXT PRIMARY KEY, synced_at INTEGER, source TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS container_runtimes (
    host TEXT, runtime TEXT, version TEXT, PRIMARY KEY (host, runtime)
);
CREATE TABLE IF NOT EXISTS containers (
    host TEXT, runtime TEXT, name TEXT, image TEXT, state TEXT, status TEXT,
    container_id TEXT, pod TEXT, PRIMARY KEY (host, runtime, name)
);
CREATE TABLE IF NOT EXISTS container_images (
    host TEXT, image_id TEXT, repo_tags TEXT, digest TEXT, size TEXT,
    fleet_filter_owned INTEGER, PRIMARY KEY (host, image_id)
);
CREATE TABLE IF NOT EXISTS container_storage (
    host TEXT, runtime TEXT, rows_json TEXT, PRIMARY KEY (host, runtime)
);
-- Stage 4 webtree audit findings (Bundle Z, task Z6 - owner ask: "these are the types of things and
-- finding i want in the web gui"). One `webtree_audits` row per host is the run summary; the file rows
-- are what the console renders, because a verdict without the path, score and reasons is a number
-- the operator cannot act on. Only files that are not `clean` get a row: a docroot of 3,879 clean
-- files is not a finding list, and the audit's own JSON stays on the host as the full record.
CREATE TABLE IF NOT EXISTS webtree_audits (
    host TEXT PRIMARY KEY, generated_at INTEGER, docroot TEXT, mode TEXT, files_total INTEGER,
    audited INTEGER, clean INTEGER, review INTEGER, quarantine INTEGER, removed INTEGER,
    errors INTEGER, report_sha TEXT, synced_at INTEGER
);
CREATE TABLE IF NOT EXISTS webtree_files (
    host TEXT, path TEXT, verdict TEXT, score INTEGER, size INTEGER, mtime INTEGER,
    reasons_json TEXT, yara_json TEXT, reused INTEGER DEFAULT 0, PRIMARY KEY (host, path)
);
-- Z7's held files. The audit says what is suspicious; the quarantine journal says what was actually
-- moved, and those are different questions with different answers. A host can have 3 quarantined
-- findings and 0 held files (everything restored), and the console has to be able to say which.
CREATE TABLE IF NOT EXISTS webtree_quarantine (
    host TEXT, source TEXT, at INTEGER, action TEXT, held_at TEXT, sha256 TEXT,
    verdict TEXT, score INTEGER, PRIMARY KEY (host, source, at, action)
);
"""


def load_registry(path):
    """Return the install list from the registry, with or without PyYAML installed.

    PyYAML is present on the fleet's Python 3.9 but not on every interpreter, and the registry is
    a flat list of simple mappings, so a 20-line fallback beats making the console unrunnable.
    """
    with open(path) as handle:
        text = handle.read()
    try:
        import yaml  # noqa: F401 - availability is the whole question here
        data = yaml.safe_load(text) or {}
        return list(data.get("installs") or [])
    except ImportError:
        pass
    installs, current = [], None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped == "installs:":
            continue
        if stripped.startswith("- "):
            current = {}
            installs.append(current)
            stripped = stripped[2:]
        if current is None or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        current[key.strip()] = value.strip().strip('"').strip("'")
    return installs


def ssh_read_raw(host, command, user="agent", timeout=25, popen=None):
    """Run an arbitrary read-only remote command and return stdout bytes.

    `popen` is the process factory, injectable so the timeout path can be tested without an SSH
    target (the same seam `web/actions.py` uses for its `runner`). The child is killed when the
    timeout fires: `communicate(timeout=...)` raises `TimeoutExpired` but leaves the process
    running, so every unreachable-or-hanging host used to leave one live `ssh` behind per sync -
    four an hour per bad host with the 15-minute timer, none of them reaped.
    """
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "%s@%s" % (user, host), command]
    with (popen or subprocess.Popen)(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            # Reported as the same IOError a failed ssh produces, so one unreachable host is still
            # just a per-host `sync_error` row rather than a failed sync of the whole fleet.
            raise IOError("ssh to %s@%s timed out after %ds%s"
                          % (user, host, timeout,
                             "; last output: %s" % err.decode("utf-8", "replace").strip() if err else ""))
    if proc.returncode != 0:
        raise IOError(err.decode("utf-8", "replace").strip() or "ssh exit %d" % proc.returncode)
    return out


def load_container_inventory(registry_path, runner=None):
    """Run `bin/container-inventory.py` for the registry and return its document, or None.

    The inventory script records per-host SSH failures inside its own document instead of failing,
    so a down host costs that host's data and nothing else. A total failure (script missing, bad
    JSON, interpreter error) also returns None rather than raising: the controller state and the
    audit stream are the console's primary job, and container telemetry must never be able to take
    them down with it.
    """
    script = os.path.join(REPO_ROOT, "bin", "container-inventory.py")
    if not os.path.exists(script):
        return None
    argv = [script, "--registry", registry_path, "--json", "-"]
    try:
        if runner is None:
            proc = subprocess.run([sys.executable] + argv, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=INVENTORY_TIMEOUT)
            payload = proc.stdout.decode("utf-8", "replace") if proc.returncode == 0 else ""
        else:
            payload = runner(argv)
    except (IOError, OSError, subprocess.SubprocessError):
        return None
    try:
        document = json.loads(payload)
    except ValueError:
        return None
    return document if isinstance(document, dict) and "hosts" in document else None


def carry_forward_containers(conn, previous_db, fqdn):
    """Copy one host's container rows from the live cache into the scratch database.

    `build_cache` assembles a brand-new database and swaps it in, so a row that is not re-inserted
    simply ceases to exist. That is the PTN-10 failure mode in a new place: an SSH timeout would make
    the console claim a host has no containers, when the truth is that the last look failed. Returns
    the previous `synced_at` so the console can still show how old the carried data is, or None when
    there is nothing to carry.
    """
    if not previous_db or not os.path.exists(previous_db):
        return None
    try:
        previous = sqlite3.connect("file:%s?mode=ro" % previous_db, uri=True, timeout=5)
    except sqlite3.Error:
        return None
    try:
        previous.row_factory = sqlite3.Row
        status = previous.execute(
            "SELECT synced_at FROM container_hosts WHERE host = ?", (fqdn,)).fetchone()
        if status is None:
            return None
        for table, columns in (("container_runtimes", ("runtime", "version")),
                               ("containers", ("runtime", "name", "image", "state", "status",
                                               "container_id", "pod")),
                               ("container_images", ("image_id", "repo_tags", "digest", "size",
                                                     "fleet_filter_owned")),
                               ("container_storage", ("runtime", "rows_json"))):
            rows = previous.execute("SELECT %s FROM %s WHERE host = ?"
                                    % (", ".join(columns), table), (fqdn,)).fetchall()
            for row in rows:
                placeholders = ",".join(["?"] * (len(columns) + 1))
                conn.execute("INSERT OR REPLACE INTO %s (host, %s) VALUES (%s)"
                             % (table, ", ".join(columns), placeholders),
                             tuple([fqdn] + [row[c] for c in columns]))
        return int(status["synced_at"] or 0)
    except sqlite3.Error:
        return None
    finally:
        previous.close()


def record_containers(conn, entry, moment, previous_db=None):
    """Write one host's inventory entry into the container tables; return the probe error, if any.

    An entry that carries an SSH error *and* no data means "we could not look", and the previous rows
    are kept on purpose: dropping them would turn a transient failure into the console claiming the
    host has no containers, which is the failure mode PTN-10 recorded for the rest of the cache.
    """
    fqdn = (entry.get("fqdn") or "").strip()
    if not fqdn:
        return "inventory entry without a host name"
    error = entry.get("ssh_error") or entry.get("probe_error") or ""
    runtimes = entry.get("runtimes") or []
    containers = entry.get("containers") or []
    images = entry.get("images") or []
    if error and not runtimes and not containers:
        carried = carry_forward_containers(conn, previous_db, fqdn)
        conn.execute("INSERT OR REPLACE INTO container_hosts (host, synced_at, source, error)"
                     " VALUES (?,?,?,?)",
                     (fqdn, moment if carried is None else carried, entry.get("source") or "", error))
        return error
    conn.execute("INSERT OR REPLACE INTO container_hosts (host, synced_at, source, error)"
                 " VALUES (?,?,?,?)", (fqdn, moment, entry.get("source") or "", error))
    for runtime in runtimes:
        conn.execute("INSERT OR REPLACE INTO container_runtimes (host, runtime, version) VALUES (?,?,?)",
                     (fqdn, runtime.get("name") or "", runtime.get("version") or ""))
    conn.execute("DELETE FROM containers WHERE host = ?", (fqdn,))
    for container in containers:
        conn.execute(
            "INSERT OR REPLACE INTO containers (host, runtime, name, image, state, status,"
            " container_id, pod) VALUES (?,?,?,?,?,?,?,?)",
            (fqdn, container.get("runtime") or "", container.get("name") or "",
             container.get("image") or "", container.get("state") or "",
             container.get("status") or "", container.get("container_id") or "",
             container.get("pod") or ""))
    conn.execute("DELETE FROM container_images WHERE host = ?", (fqdn,))
    for image in images:
        conn.execute(
            "INSERT OR REPLACE INTO container_images (host, image_id, repo_tags, digest, size,"
            " fleet_filter_owned) VALUES (?,?,?,?,?,?)",
            (fqdn, image.get("image_id") or "", ",".join(image.get("repo_tags") or []),
             image.get("digest") or "", image.get("size") or "",
             1 if image.get("fleet_filter_owned") else 0))
    conn.execute("DELETE FROM container_storage WHERE host = ?", (fqdn,))
    for runtime, rows in sorted((entry.get("storage") or {}).items()):
        conn.execute("INSERT OR REPLACE INTO container_storage (host, runtime, rows_json)"
                     " VALUES (?,?,?)", (fqdn, runtime, json.dumps(rows, sort_keys=True)))
    return error


def is_local_host(fqdn):
    """True when `fqdn` names this machine, so its files can be read without an SSH round trip.

    The registry lists the control node as an install, and `ssh agent@build01` does work, but
    answering "what is on this host" by connecting to yourself is slow and depends on a key the
    service may not have - running the sync as root produced `Permission denied (publickey)` and
    reported the control node as unreachable. The container inventory already resolves the local host
    this way; the audit path now agrees with it instead of keeping two answers for one question.
    """
    target = (fqdn or "").strip().lower()
    if not target:
        return False
    names = {socket.gethostname(), socket.getfqdn(), os.uname()[1]}
    return any(target == name.lower() for name in names if name)


def read_host_file(fqdn, ssh_user, path, timeout=25):
    """Read one file from a host: directly when it is this host, over the read-only SSH path otherwise.

    The local read falls back to `sudo -n cat` because root-owned artifacts are not always
    agent-readable, and "the file exists but I may not read it" must not be reported as "this host has
    no data". The remote path is the same `ssh_read_raw` the controller state uses, so a hanging host
    costs a killed child and a per-host error rather than a hung sync.
    """
    if is_local_host(fqdn):
        # Ask the filesystem before asking sudo. A file that does not exist is not a file we lack
        # permission to read, and under this service's `NoNewPrivileges=yes` every `sudo -n` fails,
        # so a missing artifact used to be reported as a sudo failure - "nothing has ever been
        # quarantined here" read as "the journal is broken". The same class of bug as the container
        # inventory probe (PTN-18): the sandbox changes the error, not the fact.
        if not os.path.exists(path):
            raise IOError("no such file: %s" % path)
        try:
            with open(path, "rb") as handle:
                return handle.read()
        except IOError:
            proc = subprocess.run(["sudo", "-n", "cat", path], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=timeout)
            if proc.returncode != 0:
                raise IOError(proc.stderr.decode("utf-8", "replace").strip()
                              or "local read exited %d" % proc.returncode)
            return proc.stdout
    return ssh_read_raw(fqdn, "sudo -n cat %s 2>/dev/null || cat %s" % (path, path),
                        ssh_user or "agent", timeout=timeout)


def report_generated_at(report):
    """Return a report's own generation time as epoch seconds, or 0 when it is missing or malformed."""
    value = (report or {}).get("generated_at") or ""
    try:
        return calendar.timegm(datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").utctimetuple())
    except ValueError:
        return 0


def _as_int(value):
    """Coerce a report field to int so one malformed record cannot cost the whole host's rows."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def carry_forward_webtree(conn, previous_db, fqdn):
    """Copy one host's audit row and file rows out of the live cache; return the number of file rows.

    The same rule the container tables follow: `build_cache` swaps the whole database, so a row that
    is not re-inserted ceases to exist, and a report we simply could not read is not evidence that the
    host has no findings. Returns 0 when there is nothing to carry, which is the honest answer.
    """
    if not previous_db or not os.path.exists(previous_db):
        return 0
    try:
        previous = sqlite3.connect("file:%s?mode=ro" % previous_db, uri=True, timeout=5)
    except sqlite3.Error:
        return 0
    try:
        previous.row_factory = sqlite3.Row
        audit = previous.execute("SELECT * FROM webtree_audits WHERE host = ?", (fqdn,)).fetchone()
        if audit is None:
            return 0
        columns = ("host", "generated_at", "docroot", "mode", "files_total", "audited", "clean",
                   "review", "quarantine", "removed", "errors", "report_sha", "synced_at")
        conn.execute("INSERT OR REPLACE INTO webtree_audits (%s) VALUES (%s)"
                     % (", ".join(columns), ",".join(["?"] * len(columns))),
                     tuple(audit[c] for c in columns))
        file_columns = ("host", "path", "verdict", "score", "size", "mtime", "reasons_json",
                        "yara_json", "reused")
        rows = previous.execute("SELECT * FROM webtree_files WHERE host = ?", (fqdn,)).fetchall()
        moved = 0
        for row in rows:
            conn.execute("INSERT OR REPLACE INTO webtree_files (%s) VALUES (%s)"
                         % (", ".join(file_columns), ",".join(["?"] * len(file_columns))),
                         tuple(row[c] for c in file_columns))
            moved += 1
        # Held files carry forward too: losing the row would make a file that is sitting in the
        # quarantine directory look like it was never moved, and the journal is the only proof of
        # where it came from.
        for row in previous.execute("SELECT * FROM webtree_quarantine WHERE host = ?",
                                    (fqdn,)).fetchall():
            conn.execute("INSERT OR REPLACE INTO webtree_quarantine (host, source, at, action,"
                         " held_at, sha256, verdict, score) VALUES (?,?,?,?,?,?,?,?)",
                         tuple(row[c] for c in ("host", "source", "at", "action", "held_at",
                                                "sha256", "verdict", "score")))
        return moved
    except sqlite3.Error:
        return 0
    finally:
        previous.close()


def record_quarantine(conn, fqdn, install):
    """Store one host's Z7 quarantine journal; return `(error, rows stored)`.

    The journal is the record of files that were moved out of the docroot, which is a different fact
    from the audit's finding list: a host can report three quarantined findings and hold none (all
    restored), and the console has to be able to tell those two states apart. A journal that does not
    exist means nothing has ever been quarantined there, which is the normal state and not an error;
    a journal that exists but cannot be parsed is reported, and its rows are left as they were.
    """
    path = (install.get("quarantine_journal") or "").strip()
    if not path:
        return "", 0
    try:
        payload = read_host_file(fqdn, install.get("ssh_user"), path)
    except (IOError, OSError, subprocess.SubprocessError) as exc:
        detail = str(exc).lower()
        if "no such file" in detail or "does not exist" in detail:
            conn.execute("DELETE FROM webtree_quarantine WHERE host = ?", (fqdn,))
            return "", 0
        return "quarantine journal: %s" % exc, 0
    try:
        journal = json.loads(payload.decode("utf-8", "replace"))
    except ValueError as exc:
        return "quarantine journal: %s" % exc, 0
    entries = journal.get("entries") if isinstance(journal, dict) else None
    if not isinstance(entries, list):
        return "quarantine journal: no entries section", 0
    conn.execute("DELETE FROM webtree_quarantine WHERE host = ?", (fqdn,))
    stored = 0
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("source"):
            continue
        conn.execute(
            "INSERT OR REPLACE INTO webtree_quarantine (host, source, at, action, held_at,"
            " sha256, verdict, score) VALUES (?,?,?,?,?,?,?,?)",
            (fqdn, entry.get("source") or "", _as_int(entry.get("at")),
             entry.get("action") or "", entry.get("held_at") or "", entry.get("sha256") or "",
             entry.get("verdict") or "", _as_int(entry.get("score"))))
        stored += 1
    return "", stored


def record_webtree(conn, install, moment, previous_db=None):
    """Store one host's webtree audit report; return (error, number of file rows stored).

    The console renders the report `bin/webtree-audit.py` wrote on the host it audited rather than
    re-running the audit per page-load or per sync: the audit owns its own incremental state, so the
    console's job is to show the last recorded answer together with its age. Only non-`clean` files get
    a row - a docroot of 3,879 clean files is not a findings list - and the full record stays in the
    report file on the host. An unreadable or unparseable report carries the previous rows forward and
    reports the failure per host, the same rule PTN-10 set for the rest of the cache.
    """
    fqdn = (install.get("fqdn") or "").strip()
    path = install.get("webtree_report") or ""
    if not fqdn or not path:
        return "", 0
    try:
        payload = read_host_file(fqdn, install.get("ssh_user"), path)
        report = json.loads(payload.decode("utf-8", "replace"))
        if not isinstance(report, dict) or not isinstance(report.get("summary"), dict):
            raise ValueError("report has no summary section")
        if not isinstance(report.get("files"), list):
            raise ValueError("report has no files section")
    except (IOError, OSError, ValueError, subprocess.SubprocessError) as exc:
        return "webtree report: %s" % exc, carry_forward_webtree(conn, previous_db, fqdn)
    summary = report.get("summary") or {}
    conn.execute("DELETE FROM webtree_audits WHERE host = ?", (fqdn,))
    conn.execute(
        "INSERT INTO webtree_audits (host, generated_at, docroot, mode, files_total, audited, clean,"
        " review, quarantine, removed, errors, report_sha, synced_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (fqdn, report_generated_at(report), report.get("root") or "", report.get("mode") or "",
         _as_int(report.get("files_total")), _as_int(report.get("files_audited")),
         _as_int(summary.get("clean")), _as_int(summary.get("review")),
         _as_int(summary.get("quarantine")), _as_int(summary.get("removed")),
         _as_int(summary.get("errors")), hashlib.sha256(payload).hexdigest()[:12], moment))
    conn.execute("DELETE FROM webtree_files WHERE host = ?", (fqdn,))
    stored = 0
    for record in report.get("files") or []:
        if not isinstance(record, dict) or not record.get("path"):
            continue
        verdict = record.get("verdict") or ""
        if verdict == "clean" or not verdict:
            # A record with no verdict is a removal record - the file disappeared since the last
            # audit. It is counted in `removed` and storing it as a finding rendered a blank pill
            # next to a 0 score and a '-' size, which read as an unexplained row.
            continue
        conn.execute(
            "INSERT OR REPLACE INTO webtree_files (host, path, verdict, score, size, mtime,"
            " reasons_json, yara_json, reused) VALUES (?,?,?,?,?,?,?,?,?)",
            (fqdn, record.get("path") or "", verdict, _as_int(record.get("score")),
             _as_int(record.get("size")), _as_int(record.get("mtime")),
             json.dumps(record.get("reasons") or []), json.dumps(record.get("yara") or []),
             1 if record.get("reused") else 0))
        stored += 1
    quarantine_error, _held = record_quarantine(conn, fqdn, install)
    return quarantine_error, stored


def build_cache(cache_path, registry_path, container_inventory=None):
    """Rebuild the cache database from the registry and every reachable host."""
    installs = load_registry(registry_path)
    # The scratch database has to be created on the same filesystem as the cache it becomes:
    # publishing is an os.replace, and renaming across a mount fails with EXDEV. The deployed
    # fleet-filter-ui-sync.service runs with PrivateTmp=yes, so /tmp is a tmpfs while the cache lives
    # on the root filesystem - the timer found this on its first run, where the same command run by
    # hand had always worked because nothing about /tmp was private.
    handle = tempfile.NamedTemporaryFile(prefix="pt-cache-", suffix=".db", delete=False,
                                         dir=os.path.dirname(os.path.abspath(cache_path)) or ".")
    handle.close()
    # "hosts" counts every registry entry; "queried" counts only the ones with a state source to
    # read, so a registry of candidates cannot be reported as 11 successfully synced hosts.
    stats = {"hosts": 0, "queried": 0, "claims": 0, "events": 0, "containers": 0,
             "webtree_findings": 0, "errors": []}
    try:
        conn = sqlite3.connect(handle.name)
        conn.executescript(SCHEMA)
        moment = int(time.time())
        for install in installs:
            fqdn = install.get("fqdn") or ""
            if not fqdn:
                continue
            stats["hosts"] += 1
            state_db = install.get("state_db") or ""
            audit_log = install.get("audit_log") or ""
            claims, events, error = [], [], ""
            if state_db:
                try:
                    # read_host_file, not ssh_read_raw: the control node is itself an install, and
                    # reading its own state.db over ssh makes the local answer depend on a key the
                    # service may not have (the same bug the webtree/journal path already fixed).
                    payload = read_host_file(fqdn, install.get("ssh_user"), state_db)
                    claims = read_claims_from_bytes(payload)
                except (IOError, OSError, subprocess.SubprocessError, sqlite3.Error) as exc:
                    error = "state.db: %s" % exc
            if audit_log and not error:
                try:
                    payload = read_host_file(fqdn, install.get("ssh_user"), audit_log)
                    events = parse_audit_lines(payload)
                except (IOError, OSError, subprocess.SubprocessError) as exc:
                    error = "audit.jsonl: %s" % exc
            if state_db or audit_log:
                stats["queried"] += 1
            carried_claims = carried_events = 0
            if error:
                stats["errors"].append("%s: %s" % (fqdn, error))
                # PTN-10: the fetch failed, so the honest answer is "last known state, and here is
                # why it is old" - not an empty claim table that reads as a cleared quarantine.
                carried_claims, carried_events = carry_forward_state(conn, cache_path, fqdn)
            stats["claims"] += len(claims) + carried_claims
            stats["events"] += len(events) + carried_events
            conn.execute("DELETE FROM installs WHERE fqdn = ?", (fqdn,))
            conn.execute(
                "INSERT INTO installs (fqdn, stage, deployed_at, ssh_user, state_db, audit_log,"
                " webtree_report, artifact_sha, notes, last_sync, sync_error, gateway_policy_mode)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (fqdn, install.get("stage") or "", install.get("deployed_at") or "",
                 install.get("ssh_user") or "", state_db, audit_log,
                 install.get("webtree_report") or "",
                 install.get("artifact_sha256") or install.get("artifact_sha") or "",
                 install.get("notes") or "", moment, error,
                 install.get("gateway_policy_mode") or ""))
            for claim in claims:
                conn.execute("INSERT OR REPLACE INTO claims (host, ip, claim_key, verdict, source,"
                             " author, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
                             (fqdn, claim["ip"], claim["claim_key"], claim["verdict"],
                              claim["source"], claim["author"], claim["created_at"],
                              claim["expires_at"]))
            for event in events:
                conn.execute("INSERT OR REPLACE INTO audit_events (host, ts, ip, action, verdict,"
                             " source, result) VALUES (?,?,?,?,?,?,?)",
                             (event["host"] or fqdn, event["ts"], event["ip"], event["action"],
                              event["verdict"], event["source"], event["result"]))
            # Stage 4 findings are collected from the report the host already has; the audit itself is
            # not re-run here (see record_webtree), so a slow docroot cannot slow the console down.
            webtree_error, findings = record_webtree(conn, install, moment, previous_db=cache_path)
            stats["webtree_findings"] += findings
            if webtree_error:
                stats["errors"].append("%s: %s" % (fqdn, webtree_error))
        container_document = container_inventory
        if container_document is None:
            container_document = load_container_inventory(registry_path)
        if container_document:
            for entry in container_document.get("hosts", []):
                container_error = record_containers(conn, entry, moment, previous_db=cache_path)
                stats["containers"] += len(entry.get("containers") or [])
                if container_error:
                    stats["errors"].append("%s: containers: %s" % (entry.get("fqdn"), container_error))
        conn.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('schema', ?)", (SCHEMA_VERSION,))
        conn.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('last_sync', ?)", (str(moment),))
        conn.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('generator', ?)",
                     ("web/sync.py",))
        conn.commit()
        conn.close()
        os.replace(handle.name, cache_path)
    except Exception:
        os.unlink(handle.name)
        raise
    return stats


def carry_forward_state(conn, previous_db, fqdn):
    """PTN-10: copy a host's previous claims and audit events when this sync could not read its state.

    `build_cache` assembles a brand-new database and swaps it in, so anything not re-inserted ceases
    to exist. For the controller's own state that meant a failed `sudo cat state.db` was rendered as
    "this host has no active claims" - a comms failure reading as a cleared quarantine, which is the
    one thing an operator must not be told when the truth is "we could not look". The container and
    webtree paths already carry forward; this is the same rule applied to claims and audit events.

    Returns the number of (claims, events) rows copied, so the caller can report them without
    double-counting the rows it inserts itself.
    """
    if not previous_db or not os.path.exists(previous_db):
        return (0, 0)
    try:
        previous = sqlite3.connect("file:%s?mode=ro" % previous_db, uri=True, timeout=5)
    except sqlite3.Error:
        return (0, 0)
    try:
        previous.row_factory = sqlite3.Row
        claims = previous.execute(
            "SELECT ip, claim_key, verdict, source, author, created_at, expires_at"
            " FROM claims WHERE host = ?", (fqdn,)).fetchall()
        events = previous.execute(
            "SELECT ts, ip, action, verdict, source, result FROM audit_events WHERE host = ?",
            (fqdn,)).fetchall()
    except sqlite3.Error:
        return (0, 0)
    finally:
        previous.close()
    for row in claims:
        conn.execute(
            "INSERT OR REPLACE INTO claims (host, ip, claim_key, verdict, source, author,"
            " created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
            (fqdn, row["ip"], row["claim_key"], row["verdict"], row["source"], row["author"],
             row["created_at"], row["expires_at"]))
    for row in events:
        conn.execute(
            "INSERT OR REPLACE INTO audit_events (host, ts, ip, action, verdict, source, result)"
            " VALUES (?,?,?,?,?,?,?)",
            (fqdn, row["ts"], row["ip"], row["action"], row["verdict"], row["source"],
             row["result"]))
    return (len(claims), len(events))


def read_claims_from_bytes(payload):
    """Open a SQLite database from bytes and return its claim rows."""
    handle = tempfile.NamedTemporaryFile(prefix="pt-state-", suffix=".db", delete=False)
    try:
        handle.write(payload)
        handle.close()
        conn = sqlite3.connect("file:%s?mode=ro" % handle.name, uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in conn.execute(
                "SELECT ip, claim_key, verdict, source, author, created_at, expires_at"
                " FROM claims").fetchall()]
        finally:
            conn.close()
    finally:
        os.unlink(handle.name)


def audit_timestamp(value):
    """Normalise an audit `ts` to a unix integer (the store writes ISO-8601 UTC strings)."""
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value or "").strip()
    if not text:
        return 0
    try:
        return int(datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc).timestamp())
    except ValueError:
        return 0


def audit_addresses(parsed):
    """Return every address an audit record concerns, tolerating both controller record shapes.

    `claim` and `revoke` records carry a single `ip`. `expire` records instead carry `addresses`
    (the full list the run removed) plus a `removed` count, because one expiry sweep covers every
    lease that lapsed in that tick. Reading only `ip` - which is what the first version of this
    syncer did - blanks the address column for every expiry and collapses a three-address sweep
    into one anonymous row on the Detections page. A record with neither field still yields one
    event with an empty address, so nothing is silently dropped.
    """
    single = parsed.get("ip")
    if isinstance(single, str) and single:
        return [single]
    if isinstance(single, (int, float)):
        return [str(single)]
    many = parsed.get("addresses")
    if isinstance(many, list):
        found = [a for a in many if isinstance(a, str) and a.strip()]
        return found or [""]
    if isinstance(many, str) and many:
        return [many]
    return [""]


def parse_audit_lines(payload):
    """Parse JSONL audit content into the console's event shape, skipping malformed lines.

    The controller's E13 record uses `event` (claim/revoke/expire/bypass) and an ISO-8601 `ts`,
    and carries its own `host`; the console stores `action` and a unix integer so every host's
    events sort on one clock. Unknown keys are ignored rather than rejected, so a controller that
    adds a field does not break the console. One record becomes one event per address it names
    (see `audit_addresses`), which is what lets an expiry sweep show up per address.
    """
    events = []
    for line in payload.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        if not isinstance(parsed, dict):
            continue
        base = {
            "host": parsed.get("host") or "",
            "ts": audit_timestamp(parsed.get("ts")),
            "action": parsed.get("event") or "",
            "verdict": parsed.get("verdict") or "",
            "source": parsed.get("source") or "",
            "result": parsed.get("result") or "",
        }
        for ip in audit_addresses(parsed):
            event = dict(base)
            event["ip"] = ip
            events.append(event)
    return events


def main(argv=None):
    """Sync every registered install into the cache and print a one-line summary."""
    parser = argparse.ArgumentParser(description="Sync Fleet Filter fleet state into the console cache")
    parser.add_argument("--registry", default=os.environ.get("PT_UI_REGISTRY", DEFAULT_REGISTRY))
    parser.add_argument("--cache", default=os.environ.get("PT_UI_DB", DEFAULT_CACHE))
    parser.add_argument("--dry-run", action="store_true", help="report what would be collected")
    args = parser.parse_args(argv)

    if args.dry_run:
        installs = load_registry(args.registry)
        print("registry: %s (%d installs)" % (args.registry, len(installs)))
        for install in installs:
            print("  %-32s stage=%-10s state_db=%s" % (install.get("fqdn"), install.get("stage"),
                                                       install.get("state_db") or "-"))
        return 0
    stats = build_cache(args.cache, args.registry)
    print("registered %d hosts, queried %d, %d claims, %d audit events, %d error(s)"
          % (stats["hosts"], stats["queried"], stats["claims"], stats["events"],
             len(stats["errors"])))
    for error in stats["errors"]:
        print("  error: %s" % error)
    return 0 if not stats["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
