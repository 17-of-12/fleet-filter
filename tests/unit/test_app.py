#!/usr/bin/env python3
"""Tests for the console HTTP layer in web/app.py (Bundle Y).

`web/actions.py` and `web/sync.py` had tests; the part that actually answers requests did not, which
is how a documented-but-missing `do_HEAD` shipped as `501 Unsupported method` on a deployed console.
These cover the response contract rather than the rendering: the status each route answers with, that
HEAD carries GET's headers and no body, what happens to a body the server cannot read, and that a
render failure is still a response instead of a dropped connection.

Runs under Python 3.9 and 3.12; needs no third-party modules.
"""

from __future__ import print_function

import base64
import importlib.util
import io
import json
import os
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "web"))

SPEC = importlib.util.spec_from_file_location("pt_app", os.path.join(ROOT, "web", "app.py"))
app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(app)

PASS = 0
FAIL = 0


def check(condition, description):
    """Record one assertion as a pass or a failure."""
    global PASS, FAIL
    if condition:
        PASS += 1
    else:
        FAIL += 1
        print("  FAIL: %s" % description)


class _Writer(object):
    """Collect the bytes a handler writes so a response can be inspected without a socket."""

    def __init__(self):
        """Start with an empty buffer, mirroring a socket file that has not been written to."""
        self.buffer = bytearray()

    def write(self, data):
        """Append the bytes the handler emitted and report how many were accepted."""
        self.buffer.extend(data if isinstance(data, bytes) else str(data).encode("utf-8"))
        return len(data)

    def flush(self):
        """Accept the socket-file flush the handler performs before returning."""
        pass


def respond(path, method="GET", headers=None, body=b"", console=None):
    """Drive one request through the real handler and return (status_line, headers, body)."""
    handler = app.Handler.__new__(app.Handler)
    handler.request_version = "HTTP/1.1"
    handler.command = method
    handler.path = path
    handler.requestline = "%s %s HTTP/1.1" % (method, path)
    handler.headers = dict(headers or {})
    handler.client_address = ("127.0.0.1", 55555)
    handler.server = None
    writer = _Writer()
    handler.wfile = writer
    handler.rfile = io.BytesIO(body)
    handler.console = console if console is not None else missing_console()
    handler.close_connection = True
    getattr(handler, "do_" + method)()
    raw = bytes(writer.buffer)
    head, _, payload = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    header_map = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        header_map[name.strip().lower()] = value.strip()
    return lines[0], header_map, payload


MISSING_DB = os.path.join(tempfile.gettempdir(), "pt-app-test-missing-cache.db")
REGISTRY = os.path.join(ROOT, "web", "installs.yaml")


def missing_console(allow_actions=False):
    """A console over a cache file that does not exist (the 'never synced' shape)."""
    return app.Console(app.Cache(MISSING_DB), REGISTRY, allow_actions=allow_actions)


def seeded_console(directory):
    """Build a cache.db with known rows in `directory` and return a Console over it.

    Most routes are tested against a missing cache; this exists because the queries that aggregate -
    `top_addresses` in particular - only run when the file is there, and their bugs are invisible
    until real rows are present.
    """
    SYNC_SPEC = importlib.util.spec_from_file_location(
        "pt_sync_for_app", os.path.join(ROOT, "web", "sync.py"))
    pt_sync = importlib.util.module_from_spec(SYNC_SPEC)
    SYNC_SPEC.loader.exec_module(pt_sync)
    db = os.path.join(directory, "cache.db")
    conn = sqlite3.connect(db)
    conn.executescript(pt_sync.SCHEMA)
    conn.execute("INSERT INTO meta (k, v) VALUES ('schema', '1')")
    conn.execute("INSERT INTO meta (k, v) VALUES ('last_sync', '1700000000')")
    for ip, source in (("198.51.100.7", "integration-h7"), ("198.51.100.7", ""),
                       ("198.51.100.8", "recovery-drill")):
        conn.execute(
            "INSERT INTO audit_events (host, ts, ip, action, verdict, source, result)"
            " VALUES (?,?,?,?,?,?,?)", ("h1.example", 1700000000, ip, "claim", "suspect", source, "ok"))
    conn.commit()
    conn.close()
    return app.Console(app.Cache(db), REGISTRY, allow_actions=False)


def seed_containers(directory):
    """Add container rows to a seeded cache so the Containers route has something real to render."""
    console = seeded_console(directory)          # creates the schema (and the audit rows)
    db = os.path.join(directory, "cache.db")
    conn = sqlite3.connect(db)
    conn.execute("INSERT OR REPLACE INTO container_hosts (host, synced_at, source, error)"
                 " VALUES ('h1.example', 1700000000, 'ssh', '')")
    conn.execute("INSERT OR REPLACE INTO container_runtimes (host, runtime, version)"
                 " VALUES ('h1.example', 'podman', '4.9.4')")
    conn.execute(
        "INSERT OR REPLACE INTO containers (host, runtime, name, image, state, status, container_id,"
        " pod) VALUES ('h1.example', 'podman', 'fleet-filter-apache-lab-web01',"
        " 'localhost/fleet-filter-apache:0.1.0', 'running', 'Up 3 days', '74abd0194d7e', '')")
    conn.execute(
        "INSERT OR REPLACE INTO container_images (host, image_id, repo_tags, digest, size,"
        " fleet_filter_owned) VALUES ('h1.example', 'sha256:88b8bed0',"
        " 'localhost/fleet-filter-apache:0.1.0', 'sha256:88b8bed0', '263', 1)")
    conn.execute("INSERT OR REPLACE INTO container_storage (host, runtime, rows_json)"
                 " VALUES ('h1.example', 'docker', ?)",
                 (json.dumps({"images": {"count": "6", "size": "2.331GB",
                                         "reclaimable": "78.1MB (3%)"}}),))
    conn.commit()
    conn.close()
    return console


def seed_webtree(directory):
    """Add a Stage 4 audit row plus its flagged files so the Webtree route renders real findings."""
    console = seeded_console(directory)
    db = os.path.join(directory, "cache.db")
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT OR REPLACE INTO webtree_audits (host, generated_at, docroot, mode, files_total,"
        " audited, clean, review, quarantine, removed, errors, report_sha, synced_at)"
        " VALUES ('h1.example', 1700000000, '/var/www/html', 'full', 3879, 3879, 3876, 2, 1, 0, 0,"
        " 'cafe1234beef', 1700000000)")
    conn.execute(
        "INSERT OR REPLACE INTO webtree_files (host, path, verdict, score, size, mtime,"
        " reasons_json, yara_json, reused) VALUES ('h1.example',"
        " '/var/www/html/dataanalysis/upload.php', 'quarantine', 17, 4310, 1700000000, ?, ?, 0)",
        (json.dumps(["eval", "base64_decode", "entropy 5.1",
                     "yara: PHP_Sink_On_Superglobal"]),
         json.dumps(["PHP_Sink_On_Superglobal"])))
    conn.execute(
        "INSERT OR REPLACE INTO webtree_files (host, path, verdict, score, size, mtime,"
        " reasons_json, yara_json, reused)"
        " VALUES ('h1.example', '/var/www/html/ai/x.js', 'review', 8, 2048, 1700000000, ?, '[]', 1)",
        (json.dumps(["minified: 91 bytes/line"]),))
    # Z7: one file still held, one that was quarantined and then put back. The console has to show
    # the difference, because "3 flagged" and "3 held" are different operational states.
    conn.execute(
        "INSERT OR REPLACE INTO webtree_quarantine (host, source, at, action, held_at, sha256,"
        " verdict, score) VALUES ('h1.example', '/var/www/html/dataanalysis/upload.php',"
        " 1700000000, 'quarantined', '/var/lib/fleet-filter/quarantine/dataanalysis/upload.php',"
        " 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0', 'quarantine', 17)")
    conn.execute(
        "INSERT OR REPLACE INTO webtree_quarantine (host, source, at, action, held_at, sha256,"
        " verdict, score) VALUES ('h1.example', '/var/www/html/ai/x.js', 1700000001, 'restored',"
        " '', 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1', 'review', 8)")
    conn.commit()
    conn.close()
    return console


# --- routing: the status every documented route answers with --------------------------------------
line, headers, payload = respond("/health", console=missing_console())
check(line == "HTTP/1.1 200 OK", "/health answers 200")
check(json.loads(payload.decode())["status"] == "ok", "/health reports status ok")
check(json.loads(payload.decode())["cache"] is False, "/health reports the cache as absent")
check(headers.get("content-type") == "application/json", "/health is served as application/json")
check(headers.get("cache-control") == "no-store", "a console response is never cacheable")

line, _, payload = respond("/api/stats", console=missing_console())
check(line == "HTTP/1.1 200 OK", "/api/stats answers 200 with no cache present")
check("installs" in json.loads(payload.decode()), "/api/stats returns the stats document")

line, _, payload = respond("/nope", console=missing_console())
check(line == "HTTP/1.1 404 Not Found", "an unknown path answers 404")
check(payload == b"not found", "the 404 body says so")

line, _, payload = respond("/", console=missing_console())
check(line == "HTTP/1.1 200 OK" and b"Fleet overview" in payload, "the dashboard renders")

# --- HEAD: the method the handler documented but did not implement --------------------------------
line_get, headers_get, body_get = respond("/health", console=missing_console())
line_head, headers_head, body_head = respond("/health", method="HEAD", console=missing_console())
check(line_head == line_get, "HEAD answers the same status as GET")
check(headers_head == headers_get, "HEAD returns exactly the headers GET returns")
check(body_head == b"", "HEAD returns no body")
check(headers_head.get("content-length") == str(len(body_get)),
      "HEAD's Content-Length is the length GET's body would have had")

line_head, headers_head, _ = respond("/nope", method="HEAD", console=missing_console())
check(line_head == "HTTP/1.1 404 Not Found", "HEAD on an unknown path is a 404, not a 501")

# --- POST body handling: refuse what cannot be read (PTN-02's lesson) -------------------------------
readonly = missing_console(allow_actions=False)
line, _, payload = respond("/actions/bypass", method="POST", body=b"host=x&state=on", console=readonly)
check(line == "HTTP/1.1 403 Forbidden", "a write against a read-only console is 403")
check(b"read-only" in payload, "the 403 explains that the write path is disabled")

line, _, payload = respond("/actions/bypass", method="POST", headers={"Content-Length": "abc"},
                           console=readonly)
check(line == "HTTP/1.1 400 Bad Request", "a non-numeric Content-Length answers 400")
check(b"invalid Content-Length" in payload, "the 400 names the header it could not parse")

line, _, payload = respond("/actions/bypass", method="POST",
                           headers={"Transfer-Encoding": "chunked"}, console=readonly)
check(line == "HTTP/1.1 400 Bad Request", "a chunked body answers 400 instead of reading as empty")

line, _, payload = respond("/actions/bypass", method="POST", headers={"Content-Length": "-4"},
                           console=readonly)
check(line == "HTTP/1.1 400 Bad Request", "a negative Content-Length answers 400")

line, _, _ = respond("/actions/other", method="POST", body=b"", console=readonly)
check(line == "HTTP/1.1 404 Not Found", "an unknown POST route is a 404")

# A body shorter than declared must not be silently accepted as a complete form.
line, _, payload = respond("/actions/bypass", method="POST",
                           headers={"Content-Length": "999"}, body=b"host=x", console=readonly)
check(line == "HTTP/1.1 403 Forbidden",
      "a body shorter than its Content-Length still reaches the read-only decision")

# --- the gated write path, exercised through the handler --------------------------------------------
# An enabled console with an unregistered host must render the rejection, not raise: this is the
# path that used to depend on `actions.execute` being importable and never raising.
gated = app.Console(app.Cache(MISSING_DB), REGISTRY, allow_actions=True, secret="tok-" + "x" * 24)


def post(body="", **extra):
    """POST to the write path with a correct Content-Length and the console's own host header."""
    payload = body.encode("ascii")
    headers = {"Host": "console.example.edu", "Content-Length": str(len(payload))}
    headers.update(extra)
    return respond("/actions/bypass", method="POST", headers=headers, body=payload, console=gated)


line, _, payload = post("host=nowhere&state=on&csrf=%s" % gated.csrf_token)
check(line == "HTTP/1.1 400 Bad Request", "an unregistered host is rejected with 400")
check(b"Rejected" in payload, "the rejection is rendered as a Rejected page")

# --- PTN-12: the write path refuses a request that did not come from a rendered page -----------------
line, _, payload = post("host=nowhere&state=on")
check(line == "HTTP/1.1 403 Forbidden" and b"CSRF" in payload,
      "a POST without the page's CSRF token is refused before the action runs")
line, _, payload = post("host=nowhere&state=on&csrf=not-the-token")
check(line == "HTTP/1.1 403 Forbidden" and b"CSRF" in payload,
      "a POST with the wrong CSRF token is refused")
line, _, payload = post("", **{"X-CSRF-Token": gated.csrf_token})
check(line == "HTTP/1.1 400 Bad Request",
      "the token is also accepted in the X-CSRF-Token header, so an XHR client need not build a form")
line, _, payload = post("", **{"X-CSRF-Token": gated.csrf_token,
                               "Origin": "https://other.example.edu"})
check(line == "HTTP/1.1 403 Forbidden" and b"Cross-origin" in payload,
      "a cross-origin POST is refused even with a valid token")
line, _, payload = post("", **{"X-CSRF-Token": gated.csrf_token,
                               "Referer": "https://console.example.edu/installs"})
check(line == "HTTP/1.1 400 Bad Request",
      "a same-origin Referer satisfies the origin check when Origin is absent")
line, _, payload = post("", **{"X-CSRF-Token": gated.csrf_token,
                               "Referer": "https://elsewhere.example/"})
check(line == "HTTP/1.1 403 Forbidden" and b"Cross-origin" in payload,
      "a foreign Referer is refused with the same 403")

# A read-only console still answers "read-only" ahead of the token check: the most common reason a
# POST fails on a deployed console is that the write path was never enabled, and that answer must not
# be hidden behind a CSRF error.
readonly = app.Console(app.Cache(MISSING_DB), REGISTRY, allow_actions=False, secret=gated.csrf_token)
line, _, payload = respond("/actions/bypass", method="POST",
                           headers={"Host": "console.example.edu", "Content-Length": "0"},
                           body=b"", console=readonly)
check(line == "HTTP/1.1 403 Forbidden" and b"read-only" in payload,
      "the read-only answer still wins over the token check")

# --- a render failure is a response, not a dropped connection ---------------------------------------
junk_fd, junk_path = tempfile.mkstemp(prefix="pt-app-test-junk-")
with os.fdopen(junk_fd, "w") as handle:
    handle.write("this file is not a sqlite database")
broken = app.Console(app.Cache(junk_path), REGISTRY, allow_actions=False)
line, _, payload = respond("/health", console=broken)
check(line == "HTTP/1.1 500 Internal Server Error",
      "a cache that will not open answers 500 instead of dropping the connection")
check(b"console render failed" in payload, "the 500 says the render failed and names the error class")
try:  # the same failure through the documented API route must behave identically
    line, _, _ = respond("/api/stats", console=broken)
    same = line == "HTTP/1.1 500 Internal Server Error"
except Exception:  # noqa: BLE001 - the point of the check is that nothing raises
    same = False
check(same, "the JSON route answers the same 500 rather than propagating the exception")
os.unlink(junk_path)

# --- the sources column: an empty source must not become a phantom second source ---------------------
with tempfile.TemporaryDirectory() as work:
    seeded = seeded_console(work)
    rows = seeded.cache.top_addresses(5)
    by_ip = dict((row["ip"], row) for row in rows)
    check(by_ip["198.51.100.7"]["sources"] == "integration-h7",
          "an address whose other rows have no source lists one source, not 'integration-h7,'")
    check(by_ip["198.51.100.7"]["events"] == 2,
          "the empty-source row is still counted in the event total it is grouped under")
    check(json.loads(respond("/api/stats", console=seeded)[2].decode())["top_addresses"][0]["ip"],
          "the seeded address reaches /api/stats")

# --- the containers route: the container inventory has to be reachable, not just collected ----------
with tempfile.TemporaryDirectory() as work:
    seeded = seed_containers(work)
    line, _, payload = respond("/containers", console=seeded)
    check(line == "HTTP/1.1 200 OK", "/containers answers 200")
    check(b"fleet-filter-apache-lab-web01" in payload,
          "the seeded container is named on the page")
    check(b"4.9.4" in payload, "the runtime version from the inventory is rendered")
    check(b"h1.example" in payload, "the host is named")
    stats = json.loads(respond("/api/stats", console=seeded)[2].decode())
    check(stats.get("containers") and stats["containers"][0]["host"] == "h1.example",
          "/api/stats carries the same container data the page renders")
    check(stats["containers"][0]["images"][0]["fleet_filter_owned"] is True,
          "image ownership survives the round trip through the cache")
    # The runtimes emit `system df` in shapes that differ from each other and from the earliest
    # capture format; the page has to render the numbers, not a row of dashes beside real data.
    check(b"2.331GB" in payload and b"images" in payload,
          "docker storage metrics render from the mapping shape the runtime actually prints")
    check(app.Console.storage_rows({"runtime": "docker", "rows": {"images": {"count": "6"}}})
          == [("images", "6", "-", "-")], "the mapping shape normalises to one row per resource")
    check(app.Console.storage_rows({"runtime": "x", "rows": [{"Type": "local", "Count": 3,
                                                             "Size": "1B",
                                                             "Reclaimable": "0B"}]})
          == [("local", 3, "1B", "0B")], "the legacy list shape still renders")
    check(app.Console.storage_rows({"runtime": "x", "rows": "unparseable"})
          == [("unparseable", "-", "-", "-")], "a value that is neither mapping nor list degrades"
          " to one labelled row instead of an exception")
    line, _, _ = respond("/containers", console=missing_console())
    check(line == "HTTP/1.1 200 OK", "/containers answers 200 with no cache (empty state, not a 404)")

# --- the gateway column: PTN-13's "advisory" mode has to be visible, not implied --------------------
check(app.Console.gateway_mode_cell({"gateway_policy_mode": "inline"}) == '<span class="pill ok">inline</span>',
      "an enforcing gateway renders its mode as an ok pill")
check("advisory" in app.Console.gateway_mode_cell({"gateway_policy_mode": "proxy"}),
      "a gateway that proxies classified traffic anyway is labelled advisory, not healthy")
check(app.Console.gateway_mode_cell({"gateway_policy_mode": ""}) == '<span class="muted">-</span>',
      "a host with no gateway renders a dash rather than a mode it does not have")
check(app.Console.gateway_policy_mode({"gateway_policy_mode": "INLINE"}) == "inline",
      "the mode is normalised to lower case before it is compared or shown")

# --- PTN-18: coverage has to be derived from evidence, not from the registry's own word -------------
check(app.Console.declared_stages("2+3-canary") == {"2", "3"},
      "the registry's `2+3-canary` spelling normalises to stages 2 and 3")
check(app.Console.declared_stages("1") == {"1"}, "a plain stage number is accepted")
check(app.Console.declared_stages("control") == set(),
      "`control` is not a stage claim, so nothing is derived from it")
check(app.Console.declared_stages("1,2/3 4") == {"1", "2", "3", "4"},
      "comma, slash and space separators are all accepted")
check(app.Console.declared_stages("7") == set(),
      "a stage outside 1-4 is ignored rather than rendered as a new stage")
check(app.Console.declared_stages("") == set() and app.Console.declared_stages(None) == set(),
      "empty and missing both mean no claim")

full_row = {"fqdn": "lab-web01.lab", "stage": "2+3-canary",
            "state_db": "/var/lib/adaptive-tarpit/state.db", "artifact_sha": "abc123def456",
            "last_sync": 1700000000, "sync_error": ""}
check(app.Console.evidenced_stages(full_row, set(), set()) == {"1", "2"},
      "a readable state.db and a recorded artifact prove stages 1 and 2")
check(app.Console.evidenced_stages(full_row, {"lab-web01.lab"}, set()) == {"1", "2", "3"},
      "a fleet-filter-apache container in the inventory is what proves stage 3")
check(app.Console.evidenced_stages(full_row, set(), {"lab-web01.lab"}) == {"1", "2", "4"},
      "a webtree audit row is what proves stage 4")
check(app.Console.evidenced_stages(dict(full_row, sync_error="ssh failed"), set(), set()) == {"2"},
      "a failed sync pass removes the stage-1 evidence: the controller was not read this time")
check(app.Console.evidenced_stages(dict(full_row, state_db=""), set(), set()) == {"2"},
      "a host with no state.db path cannot claim stage 1 however the registry is worded")
check(app.Console.evidenced_stages({"fqdn": "build01.lab", "stage": "control",
                                    "artifact_sha": "abc"}, set(), set()) == set(),
      "a control node has no stages to evidence, even though it holds a gateway artifact (it builds it)")

check(app.Console.stages_cell(full_row, set(), set())
      == '<span class="pill ok">1 2</span> <span class="pill warn">unproven: 3</span>',
      "a host claiming 2+3 that only proves 2 is labelled with the missing stage, not just the number")
check(app.Console.stages_cell(dict(full_row, stage="2"), set(), set())
      == '<span class="pill ok">1 2</span>',
      "a fully proven claim renders without a warn pill")
check(app.Console.stages_cell({"fqdn": "x", "stage": "control"}, set(), set()) == '<span class="muted">-</span>',
      "the control node renders a dash instead of a stage list")
check("unproven: 1,2,3" in app.Console.stages_cell(
        {"fqdn": "x", "stage": "1+2+3", "state_db": "", "artifact_sha": "", "last_sync": None},
        set(), set()),
      "every unproven stage is named, so a bare claim cannot pass as coverage")

# --- the webtree route: Stage 4 findings have to be reachable, not just collected -------------------
with tempfile.TemporaryDirectory() as work:
    seeded = seed_webtree(work)
    line, _, payload = respond("/webtree", console=seeded)
    check(line == "HTTP/1.1 200 OK", "/webtree answers 200")
    check(b"/var/www/html/dataanalysis/upload.php" in payload, "the flagged file path is rendered")
    check(b"PHP_Sink_On_Superglobal" in payload,
          "the yara rule that fired is shown - a verdict without a reason is a number to re-derive")
    check(b"quarantine" in payload and b"review" in payload, "both verdicts render with their pills")
    check(b"3879" in payload, "the summary states the tree size the findings were flagged out of")
    stats = json.loads(respond("/api/stats", console=seeded)[2].decode())
    check(stats.get("webtree") and stats["webtree"][0]["files_total"] == 3879,
          "/api/stats carries the audit summary the page renders")
    check(app.Cache(os.path.join(work, "cache.db")).webtree_totals() == (2, 2, 1, 1),
          "webtree_totals counts flagged files, review, quarantine, and hosts")
    # Z7 surface: the held file is listed, the restored one is counted as restored and not held.
    hosts = app.Cache(os.path.join(work, "cache.db")).webtree()
    check(hosts[0]["held"] == [{"path": "/var/www/html/dataanalysis/upload.php", "at": 1700000000,
                               "held_at": "/var/lib/fleet-filter/quarantine/dataanalysis/upload.php",
                               "sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
                               "verdict": "quarantine", "score": 17}],
          "the still-held file is reported from the journal, not inferred from the audit")
    check(hosts[0]["restored_count"] == 1,
          "a restored file counts as restored rather than still held")
    check(b"/var/lib/fleet-filter/quarantine/dataanalysis/upload.php" in payload,
          "the holding path is rendered, so an operator can find the file without reading the tool")
    check(b"1 restored" in payload, "the restored count is rendered alongside the held file")
    check(b"files to review" in respond("/", console=seeded)[2],
          "the dashboard gains a webtree card when an audit exists")
    check(app.json_list("{not json") == [] and app.json_list('{"a": 1}') == [],
          "a malformed reasons cell degrades to empty instead of a 500")
    line, _, _ = respond("/webtree", console=missing_console())
    check(line == "HTTP/1.1 200 OK", "/webtree answers 200 with no cache (empty state, not a 404)")

# --- the auth header contract the console depends on --------------------------------------------------
basic = "Basic " + base64.b64encode(b"admin:pw").decode("ascii")
check(app.authenticated_user({"X-Forwarded-User": "admin", "Authorization": basic}) == "admin",
      "PTN-12: the authenticated Basic credential wins over a client-settable forwarded header")
check(app.authenticated_user({"X-Forwarded-User": "forgeable",
                             "Authorization": "Basic " + base64.b64encode(b"real:pw").decode()}) == "real",
      "PTN-12: a forged X-Forwarded-User cannot rename the authenticated actor")
check(app.authenticated_user({"X-Forwarded-User": "admin"}) == "admin",
      "the forwarded identity Apache sets is the actor the console records")
check(app.authenticated_user({"X-Forwarded-User": "(null)", "Authorization": basic}) == "admin",
      "Apache's `(null)` placeholder falls back to the Basic credential")

print("test_app.py: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
