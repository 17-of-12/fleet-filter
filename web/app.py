#!/usr/bin/env python3
"""Fleet Filter fleet console - the read side of the controller, on the web.

Purpose
-------
Everything the controller already knows lives in SQLite and JSONL on each host, and reading it
means SSHing to that host. This console renders the same facts for the whole fleet: which hosts
run Fleet Filter and at what stage, which addresses were detected and by what, what is quarantined
right now, and what the trend looks like. It is deliberately read-only: enforcement stays in the
controller, so the console cannot become a second place where state changes.

Data source
-----------
`web/sync.py` pulls each registered host's `state.db` and `audit.jsonl` over SSH into
`/var/lib/fleet-filter-ui/cache.db`. The console reads only that cache, so it answers in
milliseconds and never blocks on a host that is down; every page states the age of the data it
rendered rather than presenting a stale number as current.

Serving model
-------------
Standard library only, bound to loopback, fronted by Apache, which owns authentication. The
console has no login logic of its own: whoever Apache authenticated is the identity recorded in
its access log and shown in the page footer.

Write path (Bundle Y2): `web/actions.py` is the only module that can change a fleet host, and it is
reachable only when the server starts with `--allow-actions`. The deployed default leaves the flag
off, so "the console is read-only" is enforced by a flag rather than by convention, and the
authenticated username is forwarded by Apache (`X-Forwarded-User`) so an action can name its actor.
"""

import argparse
import base64
import datetime
import html
import json
import hmac
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import actions as console_actions  # sibling module: the gated write path (Bundle Y2)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB = "/var/lib/fleet-filter-ui/cache.db"
DEFAULT_REGISTRY = os.path.join(REPO_ROOT, "web", "installs.yaml")
SCHEMA_VERSION = "1"
STALE_AFTER = 3600  # seconds; past this the cache age is shown as a warning, not in normal ink
# PTN-18: the four stages the console is allowed to claim coverage for. Anything the registry writes
# outside this set is ignored rather than rendered, so a typo cannot become a visible "stage".
STAGE_NUMBERS = ("1", "2", "3", "4")

STYLES = r"""
:root {
  --bg: #f7f8fa; --surface: #ffffff; --ink: #101828; --muted: #667085; --line: #e4e7ec;
  --accent: #3538cd; --accent-soft: #eef2ff; --ok: #067647; --ok-soft: #ecfdf3;
  --warn: #b54708; --warn-soft: #fffaeb; --bad: #b42318; --bad-soft: #fef3f2;
  --shadow: 0 1px 2px rgba(16,24,40,.06), 0 1px 3px rgba(16,24,40,.04);
  --radius: 12px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1017; --surface: #141922; --ink: #e6e8ec; --muted: #98a2b3; --line: #242b38;
    --accent: #9ba9ff; --accent-soft: #1b2040; --ok: #47cd89; --ok-soft: #10261c;
    --warn: #fdb022; --warn-soft: #2a2113; --bad: #fda29b; --bad-soft: #2b1614;
    --shadow: 0 1px 2px rgba(0,0,0,.4);
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 400 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue",
        Arial, "Noto Sans", sans-serif;
  font-variant-numeric: tabular-nums;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap { max-width: 1140px; margin: 0 auto; padding: 0 24px 64px; }

header.top {
  position: sticky; top: 0; z-index: 10; background: color-mix(in srgb, var(--bg) 88%, transparent);
  backdrop-filter: saturate(180%) blur(8px); border-bottom: 1px solid var(--line);
}
header.top .inner { max-width: 1140px; margin: 0 auto; padding: 14px 24px; display: flex;
  align-items: center; gap: 20px; flex-wrap: wrap; }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 600; letter-spacing: -.01em; }
.mark { width: 26px; height: 26px; border-radius: 8px; background: var(--accent);
  color: var(--surface); display: grid; place-items: center; font-size: 12px; font-weight: 700; }
nav.main { display: flex; gap: 4px; margin-left: auto; flex-wrap: wrap; }
nav.main a { padding: 6px 12px; border-radius: 8px; color: var(--muted); font-size: 14px; }
nav.main a:hover { background: var(--surface); color: var(--ink); text-decoration: none; }
nav.main a.on { background: var(--accent-soft); color: var(--accent); font-weight: 600; }

h1 { font-size: 24px; line-height: 1.25; margin: 28px 0 4px; letter-spacing: -.02em; }
h2 { font-size: 12px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted);
  margin: 32px 0 10px; font-weight: 600; }
.sub { color: var(--muted); margin: 0 0 8px; font-size: 14px; }

.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px;
  margin-top: 20px; }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 16px 18px; box-shadow: var(--shadow); }
.card .k { font-size: 12px; text-transform: uppercase; letter-spacing: .07em; color: var(--muted);
  font-weight: 600; }
.card .v { font-size: 30px; font-weight: 650; letter-spacing: -.02em; margin-top: 6px;
  font-variant-numeric: tabular-nums; }
.card .s { font-size: 12px; color: var(--muted); margin-top: 2px; }
.card.warn .v { color: var(--warn); }
.card.ok .v { color: var(--ok); }

.panel { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
  box-shadow: var(--shadow); overflow: hidden; }
.panel + .panel { margin-top: 16px; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: start; }
@media (max-width: 860px) { .grid2 { grid-template-columns: 1fr; } }
.panel .head { padding: 12px 18px; border-bottom: 1px solid var(--line); font-size: 12px;
  text-transform: uppercase; letter-spacing: .08em; color: var(--muted); font-weight: 600; }
.panel .body { padding: 6px 18px 14px; }

table { width: 100%; border-collapse: collapse; font-size: 14px; }
.nowrap { white-space: nowrap; }
th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .07em;
  color: var(--muted); font-weight: 600; padding: 10px 12px; border-bottom: 1px solid var(--line); }
td { padding: 10px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: color-mix(in srgb, var(--accent-soft) 45%, transparent); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
.empty { padding: 22px 18px; color: var(--muted); font-size: 14px; }
pre { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px; white-space: pre-wrap; word-break: break-word; }

/* Y2 bypass control, rendered inside a table cell on /installs. */
form.inline { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
form.inline select, form.inline input {
  font: inherit; font-size: 12px; color: var(--ink); background: var(--surface);
  border: 1px solid var(--line); border-radius: 8px; padding: 4px 8px; }
form.inline input.tiny { width: 78px; }
form.inline input[type=text] { width: 116px; }
form.inline button {
  font: inherit; font-size: 12px; font-weight: 600; color: #fff; background: var(--accent);
  border: 1px solid var(--accent); border-radius: 8px; padding: 4px 10px; cursor: pointer; }
form.inline button:hover { filter: brightness(1.06); }
@media (prefers-color-scheme: dark) { form.inline button { color: #0d1017; } }

.pill { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 12px;
  font-weight: 600; border: 1px solid transparent; white-space: nowrap; }
.pill.ok { background: var(--ok-soft); color: var(--ok); border-color: color-mix(in srgb, var(--ok) 25%, transparent); }
.pill.warn { background: var(--warn-soft); color: var(--warn);
  border-color: color-mix(in srgb, var(--warn) 25%, transparent); }
.pill.bad { background: var(--bad-soft); color: var(--bad);
  border-color: color-mix(in srgb, var(--bad) 25%, transparent); }
.pill.neutral { background: var(--accent-soft); color: var(--accent);
  border-color: color-mix(in srgb, var(--accent) 22%, transparent); }
.pill.plain { background: transparent; color: var(--muted); border-color: var(--line); }

.bars { display: grid; gap: 8px; padding: 14px 18px 16px; }
.bars .row { display: grid; grid-template-columns: 84px 1fr 48px; align-items: center; gap: 10px;
  font-size: 13px; color: var(--muted); }
.bars .track { height: 8px; border-radius: 999px; background: var(--line); overflow: hidden; }
/* display:block is required: .fill is a nested span, and width/height do not apply to a
   non-replaced inline box, so without it the accent bar collapses and no bar renders at all. */
.bars .fill { display: block; height: 100%; border-radius: 999px; background: var(--accent); }
.bars .n { text-align: right; color: var(--ink); font-variant-numeric: tabular-nums; }

footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted);
  font-size: 12.5px; display: flex; gap: 12px; flex-wrap: wrap; justify-content: space-between; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px;
  background: var(--accent-soft); padding: 1px 5px; border-radius: 5px; }
@media print { header.top, footer { display: none; } body { background: #fff; color: #000; } }
"""

WEBTREE_ROWS_PER_HOST = 50

NAV = [("/", "Dashboard"), ("/installs", "Installs"), ("/detections", "Detections"),
       ("/containers", "Containers"), ("/webtree", "Webtree"), ("/reports", "Reports"),
       ("/api/stats", "JSON")]


def utc(moment):
    """Render a unix timestamp as an ISO-8601 UTC string, or a dash when absent."""
    if not moment:
        return "-"
    return datetime.datetime.fromtimestamp(int(moment), datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def now():
    """Return the current unix time as an integer (the single clock used by the console)."""
    return int(time.time())


def humanize_age(seconds):
    """Render an age in seconds as a short human string (the console's staleness vocabulary)."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "%ds" % seconds
    if seconds < 3600:
        return "%dm" % (seconds // 60)
    if seconds < 86400:
        return "%dh" % (seconds // 3600)
    return "%dd" % (seconds // 86400)


def humanize_bytes(count):
    """Render a byte count the way the container pages render image sizes (1.05 GB, not 1127428966)."""
    try:
        size = float(count)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return ("%d%s" % (size, unit)) if unit == "B" else ("%.4g%s" % (size, unit))
        size /= 1024.0
    return "-"


def json_list(text):
    """Parse a stored JSON array, returning [] for anything that is not one.

    The cache stores `reasons` and `yara` as JSON text. A cell that cannot be parsed used to take the
    whole page down with a 500, which is the console's oldest failure mode: the render path must degrade
    to an empty list rather than refuse to answer.
    """
    try:
        value = json.loads(text or "[]")
    except (TypeError, ValueError):
        return []
    return value if isinstance(value, list) else []


def shell(title, active, body, user="anonymous"):
    """Wrap page body markup in the console chrome and return the full document."""
    links = []
    for href, label in NAV:
        cls = ' class="on"' if href == active else ""
        links.append("<a%s href=\"%s\">%s</a>" % (cls, href, html.escape(label)))
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>%s &middot; Fleet Filter</title><style>%s</style></head><body>"
        "<header class=\"top\"><div class=\"inner\">"
        "<div class=\"brand\"><span class=\"mark\">PT</span><span>Fleet Filter</span></div>"
        "<nav class=\"main\">%s</nav></div></header>"
        "<main class=\"wrap\">%s</main>"
        "<footer class=\"wrap\"><span>Fleet Filter fleet console &middot; v0.1 &middot; "
        "read-only view of controller state</span><span>rendered %s &middot; authenticated as %s"
        "</span></footer></body></html>"
        % (html.escape(title), STYLES, "".join(links), body, utc(now()), html.escape(user))
    )


def table(headers, rows, numeric=()):
    """Render an HTML table; `numeric` marks column indexes to right-align."""
    head = "".join(
        '<th%s>%s</th>' % (' class="num"' if i in numeric else "", html.escape(h))
        for i, h in enumerate(headers))
    body = []
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            cls = ' class="num"' if i in numeric else ""
            cells.append("<td%s>%s</td>" % (cls, cell))
        body.append("<tr>%s</tr>" % "".join(cells))
    return '<div class="panel"><table><thead>%s</thead><tbody>%s</tbody></table></div>' % (head, "".join(body))


def panel(title, inner):
    """Wrap pre-rendered markup in a titled panel."""
    return ('<section class="panel"><div class="head">%s</div><div class="body">%s</div></section>'
            % (html.escape(title), inner))


def card(value, label, tone="", sub=""):
    """Render one KPI card; `tone` is '', 'ok' or 'warn'."""
    cls = "card %s" % tone if tone else "card"
    extra = '<div class="s">%s</div>' % html.escape(sub) if sub else ""
    return '<div class="%s"><div class="k">%s</div><div class="v">%s</div>%s</div>' % (
        cls, html.escape(label), html.escape(str(value)), extra)


def bar_rows(rows, label_key, value_key, width=None):
    """Render a CSS bar list (no chart library) from [{label, value}] rows."""
    if not rows:
        return '<div class="empty">nothing to chart yet</div>'
    peak = max(int(r[value_key]) for r in rows) or 1
    out = ['<div class="bars">']
    for row in rows:
        value = int(row[value_key])
        pct = max(2, int(round(100.0 * value / peak)))
        out.append('<div class="row"><span>%s</span><span class="track">'
                   '<span class="fill" style="width:%d%%"></span></span>'
                   '<span class="n">%d</span></div>'
                   % (html.escape(str(row[label_key])), pct, value))
    out.append("</div>")
    return "".join(out)


def pill(text, tone="plain"):
    """Render a status pill (`tone`: ok | warn | bad | neutral | plain)."""
    return '<span class="pill %s">%s</span>' % (tone, html.escape(str(text)))


def authenticated_user(headers):
    """Resolve the acting identity, preferring the credential Apache authenticated over a header.

    PTN-12: the order used to be `X-Forwarded-User` first, which is a header any client that can
    reach the app port can set - Apache *sets* it from REMOTE_USER, but it is also just a header, and
    the app listens on its own port behind mod_proxy. The `Authorization` credential is what was
    actually authenticated, so it now wins whenever both are present; the forwarded header remains the
    source for configurations that strip `Authorization` before proxying. Apache's literal `(null)`
    is still ignored, and a genuinely unauthenticated request still resolves to `anonymous`.

    The actor is what the controller records as the person who disabled enforcement, so a name the
    client chooses is the wrong answer when a real identity is available.
    """
    auth = (headers.get("Authorization") or "").strip()
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth.split(" ", 1)[1].strip()).decode("utf-8", "replace")
        except Exception:  # malformed base64 is not an identity
            decoded = ""
        if ":" in decoded and decoded.split(":", 1)[0]:
            return decoded.split(":", 1)[0]
    forwarded = (headers.get("X-Forwarded-User") or "").strip()
    if forwarded and forwarded != "(null)":
        return forwarded
    return "anonymous"


def bypass_form(fqdn, csrf=""):
    """Render the inline bypass control for one registered host (Y2).

    One form per row rather than a separate page: the operator deciding "is this host's enforcement
    off?" is already looking at that host's row, and a form inside a table cell keeps the action next
    to the evidence that prompted it. `off` ignores the TTL field, which the controller enforces too
    (see `web/actions.normalise`) - the UI refuses first so the mistake is reported before a request.
    """
    return ('<form class="inline" method="post" action="/actions/bypass">'
            '<input type="hidden" name="host" value="%s">'
            '<input type="hidden" name="csrf" value="%s">'
            '<select name="state"><option value="on">on</option>'
            '<option value="off">off</option></select>'
            '<input class="tiny" type="number" name="ttl" value="3600" min="60" max="604800">'
            '<input class="tiny" type="text" name="reason" placeholder="reason" maxlength="120">'
            '<button type="submit">set</button></form>'
            % (html.escape(fqdn, quote=True), html.escape(csrf, quote=True)))


class Cache(object):
    """Read-only view over the synced fleet cache, with the queries every page needs."""

    def __init__(self, path):
        """Open the cache read-only so a page render cannot mutate synced state."""
        self.path = path
        self._lock = threading.Lock()

    def exists(self):
        """Report whether a cache file is present (the console works but reports 'never synced')."""
        return os.path.exists(self.path)

    def connect(self):
        """Open a SQLite connection in read-only mode."""
        conn = sqlite3.connect("file:%s?mode=ro" % self.path, uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def meta(self):
        """Return the cache metadata (schema version, last sync, generator)."""
        if not self.exists():
            return {}
        with self._lock, self.connect() as conn:
            rows = conn.execute("SELECT k, v FROM meta WHERE k IN ('schema','last_sync','generator')").fetchall()
        return {r["k"]: r["v"] for r in rows}

    def installs(self):
        """Return every registered install with its sync freshness."""
        if not self.exists():
            return []
        with self._lock, self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM installs ORDER BY fqdn").fetchall()]

    def claim_summary(self):
        """Return active/expired claim counts per host."""
        if not self.exists():
            return []
        with self._lock, self.connect() as conn:
            rows = conn.execute("""
                SELECT host,
                       SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END) AS active,
                       SUM(CASE WHEN expires_at <= ? THEN 1 ELSE 0 END) AS expired,
                       COUNT(*) AS total
                FROM claims GROUP BY host ORDER BY host""", (now(), now())).fetchall()
        return [dict(r) for r in rows]

    def verdict_breakdown(self):
        """Return active claim counts grouped by verdict (suspect/confirmed/...)."""
        if not self.exists():
            return []
        with self._lock, self.connect() as conn:
            rows = conn.execute("""
                SELECT verdict, COUNT(*) AS n FROM claims
                WHERE expires_at > ? GROUP BY verdict ORDER BY n DESC""", (now(),)).fetchall()
        return [dict(r) for r in rows]

    def detections(self, limit=200, host=None, action=None):
        """Return the most recent audit events, optionally filtered by host or action."""
        if not self.exists():
            return []
        sql = ["SELECT * FROM audit_events WHERE 1=1"]
        args = []
        if host:
            sql.append("AND host = ?")
            args.append(host)
        if action:
            sql.append("AND action = ?")
            args.append(action)
        sql.append("ORDER BY ts DESC LIMIT ?")
        args.append(int(limit))
        with self._lock, self.connect() as conn:
            return [dict(r) for r in conn.execute(" ".join(sql), args).fetchall()]

    def detections_by_day(self, days=14):
        """Return detection counts per UTC day across the trailing window, gaps included."""
        if not self.exists():
            return []
        since = now() - (days - 1) * 86400
        counts = {}
        with self._lock, self.connect() as conn:
            rows = conn.execute("""
                SELECT strftime('%Y-%m-%d', ts, 'unixepoch') AS day, COUNT(*) AS n
                FROM audit_events WHERE ts >= ? GROUP BY day""", (since,)).fetchall()
            for row in rows:
                counts[row["day"]] = int(row["n"])
        out = []
        for offset in range(days):
            day = (datetime.datetime.fromtimestamp(since, datetime.timezone.utc)
                   + datetime.timedelta(days=offset)).strftime("%Y-%m-%d")
            out.append({"day": day, "n": counts.get(day, 0)})
        return out

    def top_addresses(self, limit=10):
        """Return the addresses with the most detections - the fleet's repeat offenders.

        `NULLIF(source, '')` is not cosmetic. 29 of the 95 rows in the deployed cache have an empty
        `source` (the controller writes some audit actions without one), and `GROUP_CONCAT` counts
        the empty string as a value, so an address seen by `integration-h7` and by nothing else
        rendered its sources as `integration-h7,` - a trailing comma that reads like a second,
        nameless source. The empty value is dropped here rather than invented, so the column shows
        what actually detected the address.
        """
        if not self.exists():
            return []
        with self._lock, self.connect() as conn:
            rows = conn.execute("""
                SELECT ip, COUNT(*) AS events, MAX(ts) AS last_seen,
                       GROUP_CONCAT(DISTINCT NULLIF(source, '')) AS sources
                FROM audit_events GROUP BY ip ORDER BY events DESC, last_seen DESC LIMIT ?""",
                                (int(limit),)).fetchall()
        return [dict(r) for r in rows]

    def source_breakdown(self):
        """Return detection counts per source (signature or rule) - the 'what caught it' view."""
        if not self.exists():
            return []
        with self._lock, self.connect() as conn:
            rows = conn.execute("""
                SELECT source, COUNT(*) AS n, MAX(ts) AS last_seen FROM audit_events
                GROUP BY source ORDER BY n DESC, last_seen DESC""").fetchall()
        return [dict(r) for r in rows]

    def container_fleet(self):
        """Return the container inventory for every synced host, newest data first.

        One dict per host: the runtime names and versions it reports, its containers, its images, and
        the `system df` rows per runtime. Hosts whose last probe failed still appear (with `error` set
        and whatever rows were last good), because "unreachable" and "has no containers" are different
        facts and the console has to be able to tell them apart.
        """
        if not self.exists():
            return []
        with self._lock, self.connect() as conn:
            hosts = conn.execute(
                "SELECT host, synced_at, source, error FROM container_hosts"
                " ORDER BY synced_at DESC, host").fetchall()
            runtimes = conn.execute("SELECT host, runtime, version FROM container_runtimes").fetchall()
            containers = conn.execute(
                "SELECT host, runtime, name, image, state, status, container_id, pod"
                " FROM containers ORDER BY host, runtime, name").fetchall()
            images = conn.execute(
                "SELECT host, image_id, repo_tags, digest, size, fleet_filter_owned"
                " FROM container_images ORDER BY host, repo_tags").fetchall()
            storage = conn.execute(
                "SELECT host, runtime, rows_json FROM container_storage ORDER BY host, runtime").fetchall()
        by_host = {}
        for row in hosts:
            entry = {"host": row["host"], "synced_at": row["synced_at"],
                     "source": row["source"] or "", "error": row["error"] or "",
                     "runtimes": [], "containers": [], "images": [], "storage": []}
            by_host[row["host"]] = entry
        for row in runtimes:
            entry = by_host.get(row["host"])
            if entry is not None:
                entry["runtimes"].append({"name": row["runtime"], "version": row["version"]})
        for row in containers:
            entry = by_host.get(row["host"])
            if entry is not None:
                entry["containers"].append({"runtime": row["runtime"], "name": row["name"],
                                            "image": row["image"], "state": row["state"],
                                            "status": row["status"], "container_id": row["container_id"],
                                            "pod": row["pod"]})
        for row in images:
            entry = by_host.get(row["host"])
            if entry is not None:
                entry["images"].append({"image_id": row["image_id"], "repo_tags": row["repo_tags"],
                                        "digest": row["digest"], "size": row["size"],
                                        "fleet_filter_owned": bool(row["fleet_filter_owned"])})
        for row in storage:
            entry = by_host.get(row["host"])
            if entry is not None:
                try:
                    rows = json.loads(row["rows_json"])
                except ValueError:
                    rows = []
                entry["storage"].append({"runtime": row["runtime"], "rows": rows})
        return [by_host[h["host"]] for h in hosts]

    def container_totals(self):
        """Return `(running, total, hosts_with_data)` for the dashboard card and the JSON API."""
        fleet = self.container_fleet()
        total = sum(len(h["containers"]) for h in fleet)
        running = sum(1 for h in fleet for c in h["containers"]
                      if c["state"].lower() in ("running", "up", "created"))
        return running, total, len(fleet)

    def webtree(self):
        """Return the Stage 4 audit for every host that has one: the run summary plus its flagged files.

        One dict per host, newest report first. `files` holds only the records that are not `clean`,
        while the summary counts still describe the whole tree - the page has to read as "3 flagged out
        of 3,879", not as "3 files exist". Hosts whose report could not be read appear through the
        carry-forward path in `web/sync.py`, so a failed fetch shows old findings rather than none.
        """
        if not self.exists():
            return []
        with self._lock, self.connect() as conn:
            audits = conn.execute("SELECT * FROM webtree_audits ORDER BY synced_at DESC, host").fetchall()
            files = conn.execute(
                "SELECT host, path, verdict, score, size, mtime, reasons_json, yara_json, reused"
                " FROM webtree_files ORDER BY host, score DESC, path").fetchall()
        by_host = {}
        order = []
        for row in audits:
            entry = dict(row)
            entry["files"] = []
            by_host[row["host"]] = entry
            order.append(row["host"])
        quarantine = self.quarantine_state()
        for row in files:
            entry = by_host.get(row["host"])
            if entry is None:
                continue
            entry["files"].append({"path": row["path"], "verdict": row["verdict"],
                                   "score": row["score"], "size": row["size"], "mtime": row["mtime"],
                                   "reasons": json_list(row["reasons_json"]),
                                   "yara": json_list(row["yara_json"]),
                                   "reused": bool(row["reused"])})
        for host in order:
            state = quarantine.get(host) or {"held": [], "restored": 0}
            by_host[host]["held"] = state["held"]
            by_host[host]["restored_count"] = state["restored"]
        return [by_host[host] for host in order]

    def quarantine_state(self):
        """Return `{host: {"held": [...], "restored": n}}` from the Z7 quarantine journal table.

        A source's current state is its most recent action: `quarantined` means the file is sitting in
        the holding directory, `restored` means it went back to its origin. Counting journal rows
        instead of resolving the latest action per source would keep reporting a restored file as
        held, which is the exact confusion the journal exists to prevent.
        """
        state = {}
        if not self.exists():
            return state
        with self._lock, self.connect() as conn:
            rows = conn.execute(
                "SELECT host, source, at, action, held_at, sha256, verdict, score"
                " FROM webtree_quarantine ORDER BY host, source, at").fetchall()
        latest = {}
        for row in rows:
            latest[(row["host"], row["source"])] = row
        for (host, _source), row in latest.items():
            bucket = state.setdefault(host, {"held": [], "restored": 0})
            if row["action"] == "quarantined":
                bucket["held"].append({"path": row["source"], "held_at": row["held_at"],
                                       "sha256": row["sha256"], "at": row["at"],
                                       "verdict": row["verdict"], "score": row["score"]})
            elif row["action"] == "restored":
                bucket["restored"] += 1
        return state

    def webtree_totals(self):
        """Return `(flagged, review, quarantine, hosts_with_data)` for the dashboard card and JSON."""
        hosts = self.webtree()
        return (sum(len(h["files"]) for h in hosts),
                sum(int(h["review"] or 0) for h in hosts),
                sum(int(h["quarantine"] or 0) for h in hosts),
                len(hosts))

    def stats(self):
        """Assemble every number the console renders, in one pass, for JSON and pages alike."""
        meta = self.meta()
        installs = self.installs()
        claims = self.claim_summary()
        return {
            "generated_at": now(),
            "generated_at_iso": utc(now()),
            "cache": {"path": self.path, "exists": self.exists(),
                      "last_sync": meta.get("last_sync"), "schema": meta.get("schema")},
            "installs": installs,
            "claims_by_host": claims,
            "verdicts": self.verdict_breakdown(),
            "detections_by_day": self.detections_by_day(),
            "top_addresses": self.top_addresses(20),
            "sources": self.source_breakdown(),
            "containers": self.container_fleet(),
            "webtree": self.webtree(),
        }


class Console(object):
    """Render every route the console serves, from a Cache."""

    def __init__(self, cache, registry_path, allow_actions=False, secret=None):
        """Bind the cache, the install registry, and whether the write path (Y2) is enabled.

        PTN-12: `secret` seeds the CSRF token the pages embed and the POST handler checks. It
        defaults to a fresh random value per process, so a token captured from one process cannot be
        replayed against another; passing it explicitly is how a test (or a future on-disk secret)
        pins the value.
        """
        self.cache = cache
        self.registry_path = registry_path
        self.allow_actions = bool(allow_actions)
        self.csrf_token = secret or secrets.token_urlsafe(32)

    def dashboard(self, user="anonymous"):
        """Render the landing page: fleet totals, verdict mix, trend, and top addresses."""
        stats = self.cache.stats()
        last_sync = stats["cache"].get("last_sync")
        age = None if not last_sync else now() - int(last_sync)
        tone = "" if age is None or age <= STALE_AFTER else "warn"
        deployed = [i for i in stats["installs"] if (i.get("stage") or "none") not in ("none", "")]
        active = sum(c["active"] for c in stats["claims_by_host"])
        total = sum(c["total"] for c in stats["claims_by_host"])
        detections_14d = sum(d["n"] for d in stats["detections_by_day"])

        body = ['<h1>Fleet overview</h1>',
                '<p class="sub">Adaptive HTTP/HTTPS tarpit and scanner quarantine &middot; '
                'stage 1 controller &middot; stage 2 security gateway &middot; stage 3 container '
                'canary &middot; stage 4 webtree audit</p>']
        body.append('<div class="cards">')
        body.append(card(len(stats["installs"]), "hosts tracked", sub="%d with fleet filter deployed" % len(deployed)))
        body.append(card(active, "addresses quarantined", tone="ok" if active else "",
                         sub="%d claims on record" % total))
        body.append(card(detections_14d, "detections, 14 days"))
        running, containers, container_hosts = self.cache.container_totals()
        body.append(card("%d/%d" % (running, containers), "containers running",
                         sub="%d host%s report%s" % (container_hosts, "s" if container_hosts != 1 else "",
                                                     "" if container_hosts != 1 else "s")))
        flagged, review, quarantine, webtree_hosts = self.cache.webtree_totals()
        body.append(card(flagged, "files to review",
                         tone="bad" if quarantine else ("warn" if review else ""),
                         sub="%d quarantined, %d to review" % (quarantine, review)
                         if webtree_hosts else "no audit synced"))
        body.append(card(humanize_age(age) if age is not None else "never", "cache age", tone=tone))
        body.append("</div>")

        body.append('<div class="grid2" style="margin-top:16px">')
        verdict_rows = [[pill(v["verdict"], "bad" if v["verdict"] == "confirmed" else "warn"),
                         str(v["n"])] for v in stats["verdicts"]]
        body.append(panel("Active verdicts",
                          table(["verdict", "addresses"], verdict_rows, numeric=(1,))
                          if verdict_rows else '<div class="empty">no active claims</div>'))
        body.append(panel("Detections per day",
                          bar_rows(stats["detections_by_day"], "day", "n")))
        body.append("</div>")

        body.append("<h2>Most-detected addresses</h2>")
        if stats["top_addresses"]:
            body.append(table(["address", "events", "last seen", "sources"],
                              [['<span class="mono">%s</span>' % html.escape(t["ip"]), str(t["events"]),
                                utc(t["last_seen"]), html.escape(t["sources"] or "-")]
                               for t in stats["top_addresses"][:10]], numeric=(1,)))
        else:
            body.append('<div class="panel"><div class="empty">no detections recorded</div></div>')
        return shell("Dashboard", "/", "".join(body), user)

    @staticmethod
    def gateway_policy_mode(row):
        """Return the registry's recorded Stage 2 quarantine mode for one host, normalised.

        The registry key is optional: a host that runs no gateway (the control node) has no mode,
        and an unknown string is kept verbatim rather than being coerced into a known one, because
        guessing here would hide a typo in the registry behind a plausible-looking pill.
        """
        return (row.get("gateway_policy_mode") or "").strip().lower()

    @classmethod
    def gateway_mode_cell(cls, row):
        """Render how the Stage 2 gateway on this host treats a request it already classified.

        PTN-13: `proxy` forwards the request to the backend anyway, which is a deliberate testing
        mode and not a healthy enforcing host, so it gets its own visible label rather than being
        hidden inside the notes. A host with no gateway (the control node) renders a dash.
        """
        mode = cls.gateway_policy_mode(row)
        if not mode:
            return '<span class="muted">-</span>'
        if mode == "proxy":
            return pill("proxy (advisory)", "warn")
        if mode in ("inline", "reject"):
            return pill(mode, "ok")
        return pill(mode, "plain")

    @staticmethod
    def declared_stages(raw):
        """Normalise a registry `stage` string into the set of stage numbers it claims.

        The registry has written the same idea three different ways over the project's life - `"2"`,
        `"2+3-canary"`, `"1"` - so the parser accepts separators and suffixes instead of forcing every
        existing row to be rewritten first. `"3-canary"` and `"3"` are the same claim.
        """
        claimed = set()
        for token in re.split(r"[+,/\s]+", (raw or "").strip().lower()):
            head = token.split("-")[0]
            if head in STAGE_NUMBERS:
                claimed.add(head)
        return claimed

    @classmethod
    def evidenced_stages(cls, row, canary_hosts, webtree_hosts):
        """Return the stages the cache can actually prove for one host, ignoring what the registry says.

        PTN-18: the console used to render the registry's `stage` string as the fleet's coverage, which
        means a hand-edited word was the only evidence behind "this host is protected". Each stage here
        is backed by the artefact that stage is supposed to have produced:

        * 1 - the controller's `state.db` was read on that host this sync pass without error;
        * 2 - a gateway artifact hash is recorded for the host (and `gateway` says what it does);
        * 3 - a `fleet-filter-apache` container is present in that host's container inventory;
        * 4 - a Stage 4 webtree audit report exists for that host.

        A control node is not a served site, so it has no stages to evidence and renders as a dash.
        """
        if (row.get("stage") or "").strip().lower() == "control":
            return set()
        host = row.get("fqdn") or ""
        proven = set()
        if (row.get("state_db") or "").strip() and row.get("last_sync") and not (row.get("sync_error") or "").strip():
            proven.add("1")
        if (row.get("artifact_sha") or "").strip():
            proven.add("2")
        if host in canary_hosts:
            proven.add("3")
        if host in webtree_hosts:
            proven.add("4")
        return proven

    @classmethod
    def stages_cell(cls, row, canary_hosts, webtree_hosts):
        """Render the declared stage next to the stages the cache can prove.

        The two are shown separately on purpose. Collapsing them into one column would let a host that
        *claims* 2+3 but only proves 2 read as healthy; the warn pill naming the missing stages is the
        part PTN-18 asked for.
        """
        declared = cls.declared_stages(row.get("stage"))
        if not declared:
            return '<span class="muted">-</span>'
        proven = cls.evidenced_stages(row, canary_hosts, webtree_hosts)
        missing = sorted(declared - proven)
        cell = pill(" ".join(sorted(proven)) or "none", "ok" if proven else "plain")
        if missing:
            cell += ' %s' % pill("unproven: %s" % ",".join(missing), "warn")
        return cell

    def installs_page(self, user="anonymous"):
        """Render the install registry: what is deployed where, and how fresh each host is."""
        rows = self.cache.installs()
        canary_hosts = {h["host"] for h in self.cache.container_fleet()
                        if any("fleet-filter-apache" in (c.get("image") or "")
                               for c in h.get("containers", []))}
        webtree_hosts = {h["host"] for h in self.cache.webtree()}
        body = ['<h1>Installs</h1>',
                '<p class="sub">Every host in <code>%s</code>, with the artifact it runs and when '
                'the console last read its state.</p>' % html.escape(self.registry_path)]
        if not rows:
            return shell("Installs", "/installs",
                         '<div class="panel"><div class="empty">no installs registered</div></div>', user)
        table_rows = []
        headers = ["host", "stage", "stages proven", "deployed", "artifact", "gateway", "last sync", "notes"]
        if self.allow_actions:
            headers = headers + ["bypass"]
        for row in rows:
            stage = row.get("stage") or "none"
            tone = "neutral" if stage in ("control",) else ("ok" if stage != "none" else "plain")
            error = row.get("sync_error") or ""
            body_cell = html.escape(row.get("notes") or "")
            if error:
                body_cell = '%s %s' % (body_cell, pill("sync error", "bad"))
            cells = [
                '<span class="mono">%s</span>' % html.escape(row["fqdn"]),
                pill(stage, tone),
                self.stages_cell(row, canary_hosts, webtree_hosts),
                '<span class="nowrap">%s</span>' % html.escape(row.get("deployed_at") or "-"),
                '<span class="mono">%s</span>' % ((row.get("artifact_sha") or "")[:12] or "-"),
                self.gateway_mode_cell(row),
                humanize_age(now() - int(row["last_sync"])) if row.get("last_sync") else "never",
                body_cell,
            ]
            if self.allow_actions:
                cells.append(bypass_form(row["fqdn"], self.csrf_token))
            table_rows.append(cells)
        body.append(table(headers, table_rows))
        return shell("Installs", "/installs", "".join(body), user)

    @staticmethod
    def storage_rows(storage):
        """Normalise one stored `system df` record into (resource, count, size, reclaimable) rows.

        The two runtimes do not agree on a shape and the sync stores what each printed: docker emits a
        mapping of resource -> {count, size, reclaimable}, podman emits the same mapping with integer
        counts, and the older capture format was a list of {Type, Count, Size, Reclaimable}. The first
        version of this page only understood the third shape, so every real host rendered a row of
        dashes next to data that was plainly present. All three are handled now.
        """
        value = storage["rows"]
        rows = []
        if isinstance(value, dict):
            for name, metrics in sorted(value.items()):
                if isinstance(metrics, dict):
                    rows.append((name,
                                 metrics.get("count", metrics.get("Count", "-")),
                                 metrics.get("size", metrics.get("Size", "-")),
                                 metrics.get("reclaimable", metrics.get("Reclaimable", "-"))))
                else:
                    rows.append((name, str(metrics), "-", "-"))
        elif isinstance(value, list):
            for entry in value:
                if isinstance(entry, dict):
                    rows.append((entry.get("Type", entry.get("type", "-")),
                                 entry.get("Count", entry.get("count", "-")),
                                 entry.get("Size", entry.get("size", "-")),
                                 entry.get("Reclaimable", entry.get("reclaimable", "-"))))
                else:
                    rows.append((str(entry), "-", "-", "-"))
        else:
            rows.append((str(value), "-", "-", "-"))
        return rows

    def containers_page(self, user="anonymous"):
        """Render the container inventory: runtime versions, containers, images, and storage per host.

        Owner ask (2026-11-16): "keep container versions listed and the like". The page answers three
        questions without an SSH session - what runtime and version a host runs, whether a container we
        own is actually up, and whether the image tag it runs still points at the digest we published.
        """
        fleet = self.cache.container_fleet()
        body = ['<h1>Containers</h1>',
                '<p class="sub">Container runtime state collected by '
                '<code>bin/container-inventory.py</code> for every host this project owns.</p>']
        if not fleet:
            return shell("Containers", "/containers",
                         '<div class="panel"><div class="empty">no container data synced yet</div></div>',
                         user)
        for host in fleet:
            inner = []
            runtimes = ", ".join("%s %s" % (r["name"], r["version"]) for r in host["runtimes"]) or "none"
            inner.append('<p class="sub">runtimes: <span class="mono">%s</span> &middot; synced %s%s</p>'
                         % (html.escape(runtimes), humanize_age(now() - int(host["synced_at"])),
                            ""
                            if not host["error"]
                            else ' &middot; %s' % pill("probe error", "bad")))
            if host["containers"]:
                inner.append(table(
                    ["container", "image", "state", "id", "pod"],
                    [["<span class=\"mono\">%s</span>" % html.escape(c["name"]),
                      "<span class=\"mono\">%s</span>" % html.escape(c["image"]),
                      pill(c["state"], "ok" if c["state"].lower() in ("running", "up") else "warn"),
                      "<span class=\"mono\">%s</span>" % html.escape((c["container_id"] or "")[:12]),
                      html.escape(c["pod"] or "-")]
                     for c in host["containers"]]))
            else:
                inner.append('<div class="panel"><div class="empty">no containers present</div></div>')
            owned = [i for i in host["images"] if i["fleet_filter_owned"]]
            if owned:
                inner.append(table(
                    ["this project's images", "digest", "size"],
                    [[html.escape(i["repo_tags"] or i["image_id"]),
                      "<span class=\"mono\">%s</span>" % html.escape((i["digest"] or "")[7:19] or "-"),
                      html.escape(i["size"] or "-")]
                     for i in owned]))
            for storage in host["storage"]:
                rows = self.storage_rows(storage)
                inner.append(table(
                    ["%s storage" % storage["runtime"], "count", "size", "reclaimable"],
                    [[html.escape(str(r[0])), html.escape(str(r[1])),
                      html.escape(str(r[2])), html.escape(str(r[3]))]
                     for r in rows]))
            body.append(panel(host["host"], "".join(inner)))
        return shell("Containers", "/containers", "".join(body), user)

    def webtree_page(self, user="anonymous"):
        """Render the Stage 4 findings: per-host audit summary and every file that was not clean.

        Owner ask (2026-11-16): "these are the types of things and finding i want in the web gui." The
        reason column is the point of the page - a verdict without a stated reason is a number the
        operator has to go and re-derive by hand, which is exactly how the `ungoliant/api.php`
        false positive ended up being read by hand anyway. Clean files are not listed; the summary
        line says how many there were.
        """
        hosts = self.cache.webtree()
        body = ['<h1>Webtree audit</h1>',
                '<p class="sub">Static analysis of each host\'s document root by '
                '<code>bin/webtree-audit.py</code> - shape metrics, yara matches, and the verdict each '
                'file earned. Only files that are not <code>clean</code> are listed.</p>']
        if not hosts:
            return shell("Webtree", "/webtree",
                         '<div class="panel"><div class="empty">no webtree audit synced yet</div></div>',
                         user)
        for host in hosts:
            inner = []
            inner.append(
                '<p class="sub">docroot: <span class="mono">%s</span> &middot; %s scan &middot; '
                'audited %s of %s files &middot; clean %s &middot; review %s &middot; quarantine %s'
                ' &middot; report %s &middot; synced %s</p>'
                % (html.escape(host["docroot"] or "-"), html.escape(host["mode"] or "-"),
                   html.escape(str(host["audited"])), html.escape(str(host["files_total"])),
                   html.escape(str(host["clean"])), html.escape(str(host["review"])),
                   html.escape(str(host["quarantine"])), html.escape(host["report_sha"] or "-"),
                   humanize_age(now() - int(host["synced_at"] or 0))))
            if host["files"]:
                shown = host["files"][:WEBTREE_ROWS_PER_HOST]
                inner.append(table(
                    ["file", "verdict", "score", "size", "modified", "why"],
                    [["<span class=\"mono\">%s</span>" % html.escape(f["path"]),
                      pill(f["verdict"], "bad" if f["verdict"] in ("quarantine", "error") else "warn"),
                      str(f["score"]), humanize_bytes(f["size"]), utc(f["mtime"]),
                      html.escape("; ".join(str(r) for r in f["reasons"]) or "-")]
                     for f in shown], numeric=(2,)))
                # The first real render of build01's own docroot was a 16,000 px page: 135 rows is not
                # a list a person reads, and the audit's own text report caps at 50 for the same reason.
                if len(host["files"]) > len(shown):
                    inner.append('<p class="sub">%d more flagged file%s not shown; the full record is in '
                                 "the report on the host (<span class=\"mono\">%s</span>).</p>"
                                 % (len(host["files"]) - len(shown), "s" if len(host["files"]) - len(shown) != 1
                                    else "", html.escape(host["docroot"] or "-")))
            else:
                inner.append('<div class="panel"><div class="empty">nothing flagged in the last audit'
                             ' (%s files, all clean)</div></div>' % html.escape(str(host["files_total"])))
            # Z7's side of the page: the audit says what is suspicious, the journal says what was
            # actually moved. Showing only the first would let a host with three restored findings
            # and nothing held read the same as one with three files sitting in quarantine.
            held = host.get("held") or []
            restored_count = int(host.get("restored_count") or 0)
            if held or restored_count:
                inner.append('<p class="sub">quarantine journal: %s held &middot; %s restored</p>'
                             % (html.escape(str(len(held))), html.escape(str(restored_count))))
                if held:
                    inner.append(table(
                        ["quarantined file", "held as", "sha256", "when", "verdict"],
                        [["<span class=\"mono\">%s</span>" % html.escape(h["path"]),
                          "<span class=\"mono\">%s</span>" % html.escape(h["held_at"] or "-"),
                          "<span class=\"mono\">%s</span>" % html.escape((h["sha256"] or "")[:12] or "-"),
                          utc(h["at"]), pill(h["verdict"] or "quarantined", "bad")]
                         for h in held[:WEBTREE_ROWS_PER_HOST]], numeric=(3,)))
            body.append(panel(host["host"], "".join(inner)))
        return shell("Webtree", "/webtree", "".join(body), user)

    def detections_page(self, params, user="anonymous"):
        """Render the detection feed with optional host and action filters."""
        host = (params.get("host") or [""])[0]
        action = (params.get("action") or [""])[0]
        rows = self.cache.detections(200, host or None, action or None)
        body = ['<h1>Detections</h1>',
                '<p class="sub">Newest 200 audit events%s%s &middot; '
                '<a href="/detections">clear filters</a></p>'
                % (" on <strong>%s</strong>" % html.escape(host) if host else "",
                   " / <strong>%s</strong>" % html.escape(action) if action else "")]
        if not rows:
            return shell("Detections", "/detections",
                         '<div class="panel"><div class="empty">no detections in the cache</div></div>',
                         user)
        tone_for = {"claim": "ok", "revoke": "plain", "expire": "plain", "bypass": "warn"}
        body.append(table(["when", "host", "address", "event", "verdict", "source", "result"],
                          [[utc(r["ts"]), '<span class="mono">%s</span>' % html.escape(r["host"]),
                            '<span class="mono">%s</span>' % html.escape(r["ip"]),
                            pill(r["action"] or "-", tone_for.get(r["action"], "plain")),
                            html.escape(r["verdict"] or "-"),
                            '<span class="mono">%s</span>' % html.escape(r["source"] or "-"),
                            html.escape(r["result"] or "-")] for r in rows]))
        return shell("Detections", "/detections", "".join(body), user)

    def reports_page(self, user="anonymous"):
        """Render per-host and per-source reports - the 'what did this catch' view."""
        stats = self.cache.stats()
        body = ['<h1>Reports</h1>',
                '<p class="sub">Aggregated from every synced host. '
                'Machine-readable form at <a href="/api/stats">/api/stats</a>.</p>']
        body.append("<h2>Per host</h2>")
        if stats["claims_by_host"]:
            body.append(table(["host", "active", "expired", "total"],
                              [['<span class="mono">%s</span>' % html.escape(c["host"]),
                                str(c["active"]), str(c["expired"]), str(c["total"])]
                               for c in stats["claims_by_host"]], numeric=(1, 2, 3)))
        else:
            body.append('<div class="panel"><div class="empty">no claims on record</div></div>')

        body.append("<h2>Detections per day (14 days)</h2>")
        body.append('<div class="panel">%s</div>' % bar_rows(stats["detections_by_day"], "day", "n"))

        body.append("<h2>Per detection source</h2>")
        if stats["sources"]:
            body.append(table(["source", "events", "last seen"],
                              [['<span class="mono">%s</span>' % html.escape(s["source"] or "-"), str(s["n"]),
                                utc(s["last_seen"])] for s in stats["sources"]], numeric=(1,)))
        else:
            body.append('<div class="panel"><div class="empty">no detections recorded</div></div>')
        return shell("Reports", "/reports", "".join(body), user)

    def render(self, path, params, user="anonymous"):
        """Route a request path to its content type and rendered body, or (None, None) for 404."""
        if path in ("/", "/index.html"):
            return "text/html; charset=utf-8", self.dashboard(user)
        if path == "/installs":
            return "text/html; charset=utf-8", self.installs_page(user)
        if path == "/containers":
            return "text/html; charset=utf-8", self.containers_page(user)
        if path == "/webtree":
            return "text/html; charset=utf-8", self.webtree_page(user)
        if path == "/detections":
            return "text/html; charset=utf-8", self.detections_page(params, user)
        if path == "/reports":
            return "text/html; charset=utf-8", self.reports_page(user)
        if path in ("/api/stats", "/stats.json"):
            return "application/json", json.dumps(self.cache.stats(), indent=1, sort_keys=True)
        if path == "/health":
            return "application/json", json.dumps(
                {"status": "ok", "service": "fleet-filter-ui", "cache": self.cache.exists(),
                 "last_sync": self.cache.meta().get("last_sync")}, sort_keys=True)
        return None, None

    def handle_post(self, path, form, user="anonymous", headers=None):
        """Route a POST to the gated write path and return (status, content_type, body_html).

        Only `/actions/bypass` exists today. Everything else is a 404, and the read-only case is a
        deliberate 403 with an explanation rather than a silent rejection, because the most likely
        reason a POST fails on the deployed console is that nobody started it with `--allow-actions`.

        PTN-12 adds the two checks a state-changing POST needs before the action runs:
        an Origin/Referer comparison against the requested host (a form posted from another site is
        refused even if it guesses every field name), and the CSRF token the rendered page embedded
        (compared with `hmac.compare_digest`, and accepted from either the form field or the
        `X-CSRF-Token` header so an XHR client is not forced to build a form body).
        """
        if path != "/actions/bypass":
            return 404, "text/html; charset=utf-8", shell("Not found", "", "<h1>not found</h1>", user)
        if not self.allow_actions:
            return 403, "text/html; charset=utf-8", shell(
                "Read-only", "", '<h1>This console is read-only</h1><p class="sub">The write path '
                'is disabled. Start the service with <code>--allow-actions</code> to enable '
                'bypass controls (Bundle Y2).</p>', user)
        headers = headers or {}
        host = (headers.get("Host") or "").strip().lower()
        origin = (headers.get("Origin") or "").strip().lower()
        referer = (headers.get("Referer") or "").strip().lower()
        if not origin and "://" in referer:
            origin = referer.split("://", 1)[1].split("/", 1)[0].lower()
        if host and origin and origin != host:
            return 403, "text/html; charset=utf-8", shell(
                "Cross-origin", "",
                '<h1>Cross-origin request refused</h1><p class="sub">This form may only be submitted '
                'from <code>%s</code>, not <code>%s</code>.</p>'
                % (html.escape(host), html.escape(origin)), user)
        supplied = ""
        if isinstance(form, dict):
            values = form.get("csrf")
            supplied = (values[0] if isinstance(values, (list, tuple)) and values else values) or ""
        supplied = supplied.strip() or (headers.get("X-CSRF-Token") or "").strip()
        if not supplied or not hmac.compare_digest(supplied, self.csrf_token):
            return 403, "text/html; charset=utf-8", shell(
                "Invalid token", "",
                '<h1>Invalid or missing CSRF token</h1><p class="sub">Reload the page and submit the '
                'form again; the token is issued by the page, not chosen by the client.</p>', user)
        try:
            action = console_actions.execute(form, self.cache.installs(), user)
        except console_actions.ActionError as exc:
            tone, lines = "bad", ['<h1>Rejected</h1>', '<p class="sub">%s</p>' % html.escape(str(exc))]
            return 400, "text/html; charset=utf-8", shell("Rejected", "", "".join(lines), user)
        tone, lines = console_actions.render_result(action)
        return 200, "text/html; charset=utf-8", shell("Bypass result", "", "".join(lines), user)


class Handler(BaseHTTPRequestHandler):
    """Serve rendered console pages; authentication is Apache's job, not this app's."""

    server_version = "fleet-filter-ui/0.1.0"
    protocol_version = "HTTP/1.1"
    console = None

    def do_GET(self):
        """Answer GET for every console route."""
        self._respond(include_body=True)

    def do_HEAD(self):
        """Answer HEAD with exactly the headers a GET would send, and no body (RFC 9110 9.3.2).

        The class used to document that HEAD was served by the GET code path while only defining
        `do_GET`, and `BaseHTTPRequestHandler` answers any method without a matching `do_<METHOD>`
        with `501 Unsupported method` - observed in production as `HTTP/1.1 501 Unsupported method
        ('HEAD')` against a console whose pages rendered fine. Monitoring probes and link checkers
        ask with HEAD, so the health of the app was being reported as a failure while the app was
        healthy. The fix routes both methods through one renderer so the two cannot drift apart.
        """
        self._respond(include_body=False)

    def _respond(self, include_body):
        """Render the current path once and answer it as either a GET or a HEAD response.

        A render failure becomes a visible 500 rather than a dropped connection: `Cache.connect()`
        raises `sqlite3.OperationalError` on a cache that is missing, half-written, or on a schema
        the running app does not know, and an exception escaping here kills the connection without
        ever writing a response or an access-log line - the one case where the console fails
        silently instead of saying what broke.
        """
        parsed = urlparse(self.path)
        user = authenticated_user(self.headers)
        try:
            content_type, body = self.console.render(parsed.path, parse_qs(parsed.query), user)
        except Exception as exc:  # noqa: BLE001 - any render failure must still produce a response
            self._send(500, "text/plain; charset=utf-8",
                       "console render failed: %s" % type(exc).__name__, include_body)
            return
        if body is None:
            self._send(404, "text/plain; charset=utf-8", "not found", include_body)
            return
        self._send(200, content_type, body, include_body)

    def _send(self, status, content_type, body, include_body=True):
        """Write one response, with or without the body, from a single code path."""
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if include_body:
            self.wfile.write(encoded)

    def do_POST(self):
        """Serve the gated write path (Y2); GET routes are unaffected by this method existing."""
        parsed = urlparse(self.path)
        raw, error = self._read_body()
        if error:
            self._send(400, "text/plain; charset=utf-8", error, True)
            return
        user = authenticated_user(self.headers)
        try:
            status, content_type, body = self.console.handle_post(
                parsed.path, parse_qs(raw), user, self.headers)
        except Exception as exc:  # noqa: BLE001 - a failed action must still answer its client
            self._send(500, "text/plain; charset=utf-8",
                       "console action failed: %s" % type(exc).__name__, True)
            return
        self._send(status, content_type, body, True)

    def _read_body(self):
        """Return (body_text, error) for a request body, refusing what cannot be read.

        This is PTN-02's lesson applied to the console. Reading the body used to be
        `int(self.headers.get("Content-Length") or 0)`, which had two failure shapes: a
        non-numeric `Content-Length` raised `ValueError` and dropped the connection, and a body
        without a `Content-Length` (chunked) was read as zero bytes and silently became an empty
        form - so a submission could be accepted as empty when the client had sent fields.
        """
        transfer_encoding = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in transfer_encoding:
            # Answering honestly beats buffering a body whose length the request never stated.
            return "", "chunked request bodies are not supported by the console"
        declared = self.headers.get("Content-Length")
        if declared is None:
            return "", ""  # a bodyless POST is a valid empty form
        try:
            length = int(declared)
        except ValueError:
            return "", "invalid Content-Length: %r" % (declared,)
        if length < 0:
            return "", "negative Content-Length: %d" % length
        return self.rfile.read(length).decode("utf-8", "replace"), ""

    def log_message(self, fmt, *args):
        """Emit one JSON line per request so the access log is ingestable like the audit log."""
        sys.stdout.write(json.dumps({
            "ts": now(), "client": self.client_address[0] if self.client_address else "-",
            "method": self.command, "path": self.path,
        }) + "\n")
        sys.stdout.flush()


def build_app(db_path, registry_path, allow_actions=False):
    """Construct the console and its handler class for the given cache, registry and write mode."""
    console = Console(Cache(db_path), registry_path, allow_actions=allow_actions)
    handler = type("ConsoleHandler", (Handler,), {"console": console})
    return console, handler


def main(argv=None):
    """Parse arguments and serve the console on loopback."""
    parser = argparse.ArgumentParser(description="Fleet Filter fleet console")
    parser.add_argument("--db", default=os.environ.get("PT_UI_DB", DEFAULT_DB),
                        help="path to the synced cache.db")
    parser.add_argument("--registry", default=os.environ.get("PT_UI_REGISTRY", DEFAULT_REGISTRY),
                        help="path to web/installs.yaml (the install registry)")
    parser.add_argument("--bind", default="127.0.0.1", help="bind address (default loopback)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PT_UI_PORT", "8188")))
    parser.add_argument("--allow-actions", dest="allow_actions",
                        default=os.environ.get("PT_UI_ALLOW_ACTIONS", "").lower() in ("1", "true", "yes"),
                        action="store_true",
                        help="enable the write path (Bundle Y2 bypass controls); default off keeps "
                             "the console read-only")
    args = parser.parse_args(argv)

    _, handler = build_app(args.db, args.registry, allow_actions=args.allow_actions)
    server = ThreadingHTTPServer((args.bind, args.port), handler)
    sys.stdout.write("fleet-filter-ui listening on http://%s:%d db=%s registry=%s\n"
                     % (args.bind, args.port, args.db, args.registry))
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
