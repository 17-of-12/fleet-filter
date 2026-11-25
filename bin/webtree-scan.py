#!/usr/bin/env python3
"""Scan a served webtree from outside the container and report what an outsider actually learns.

Why this exists
---------------
Stage 4 of the Fleet Filter design is "what does a real external scanner see and how long does it
stay?" - the review records it as unimplemented (PTN-18), and the X4 soak cannot answer it either
because a soak with no scanner traffic measures nothing about engagement. This script is the
measurement half of that question, and it is deliberately not a generic content brute-forcer: it
answers the two things the project cares about.

1. **What leaks.** Requesting the paths a host really serves tells a scanner the file names, sizes,
   modification dates, and the `Server:` / `X-Powered-By:` banner - even when the answer is a 403.
   A tarpit that denies a request while returning the real banner and the real byte count has told
   the scanner the file exists.
2. **What the tarpit's answer looks like.** Every response is timed, so a slow-drip answer (the
   responder's signature) is distinguishable from an instant Apache 403, and a set of responses that
   all carry the same banner can be compared against the deception catalogue's claimed identity.

Paths come from one of two places: a file, or the live docroot of a registered host pulled over SSH
(the latter is what makes this a scan of *the webtree* rather than a wordlist guess). Output is a
table plus a JSON document, so a soak run can archive the result the way it archives latency.

Examples
--------
    # what does lab-web01's :80 vhost leak, using the paths it really serves?
    bin/webtree-scan.py --target http://10.30.72.19 --from-host lab-web01.lab

    # scan a specific vhost by name on an address that has several
    bin/webtree-scan.py --target https://lab-web01.lab --host-header lab-web01.lab \\
        --paths-file paths.txt --out data/results/webtree-2026-11-16.json
"""

from __future__ import print_function

import argparse
import http.client
import json
import os
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

# Headers a scanner uses to fingerprint the stack. Anything else is per-response noise.
FINGERPRINT_HEADERS = ("server", "x-powered-by", "x-content-type-options", "content-type")
# Verdicts a response can be sorted into; the counts are the summary an operator reads first.
CLASSES = ("served", "redirect", "denied", "not_found", "error", "other")


def parse_args(argv=None):
    """Parse the command line into the scan's target, path source, and reporting options."""
    parser = argparse.ArgumentParser(description="Scan a served webtree from outside the container")
    parser.add_argument("--target", required=True,
                        help="base URL to scan, e.g. http://10.30.72.19 or https://host.example")
    parser.add_argument("--host-header", default=None,
                        help="Host header to send, for addresses serving several vhosts")
    parser.add_argument("--paths-file", default=None,
                        help="file of paths to request (one per line), or - for stdin")
    parser.add_argument("--from-host", default=None,
                        help="SSH to this host and derive the path list from its docroot")
    parser.add_argument("--docroot", default="/var/www/html",
                        help="docroot to enumerate with --from-host (default: /var/www/html)")
    parser.add_argument("--limit", type=int, default=200,
                        help="maximum paths to request (default: 200)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="seconds allowed per request before it counts as a failure")
    parser.add_argument("--slow-ms", type=float, default=1000.0,
                        help="a response slower than this is flagged as a drip (default: 1000 ms)")
    parser.add_argument("--out", default=None, help="write the full result JSON here")
    parser.add_argument("--insecure", action="store_true", default=None,
                        help="do not verify the TLS certificate (default for https targets)")
    return parser.parse_args(argv)


def normalise_target(target):
    """Return (scheme, host, port) for a target URL, filling in the scheme's default port."""
    parts = urlsplit(target if "//" in target else "http://" + target)
    scheme = parts.scheme or "http"
    port = parts.port or (443 if scheme == "https" else 80)
    return scheme, parts.hostname, port


def paths_from_file(spec):
    """Read paths from a file, or from stdin when the spec is `-`.

    Blank lines and `#` comments are skipped so a captured docroot listing can be annotated.
    """
    if spec == "-":
        lines = sys.stdin.read().splitlines()
    else:
        with open(spec) as handle:
            lines = handle.read().splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def paths_from_host(host, docroot):
    """Derive the path list from a live host's docroot over SSH.

    `sudo -n find` is required because docroots are root-owned on every host in the fleet, and the
    listing is the point: a scanner with a wordlist guesses names, whereas this tells us exactly
    which names the host is willing to answer for, so a leak is attributable rather than suspected.
    """
    command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host,
               "sudo -n find %s -type f 2>/dev/null | head -500" % docroot]
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=60, check=False)
    except subprocess.TimeoutExpired:
        raise SystemExit("webtree-scan: ssh to %s timed out" % host)
    if completed.returncode != 0:
        raise SystemExit("webtree-scan: cannot list %s on %s: %s"
                         % (docroot, host, completed.stderr.decode(errors="replace").strip()))
    paths = []
    for line in completed.stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        relative = line[len(docroot):] if line.startswith(docroot) else "/" + os.path.basename(line)
        paths.append(relative if relative.startswith("/") else "/" + relative)
    return paths


def request_one(scheme, host, port, path, host_header, timeout, insecure):
    """Issue one GET and return (status, bytes, ttfb_ms, headers) or raise on transport failure.

    TTFB is measured as the interval to receiving the status line and headers, which is what a
    client experiences as first byte; the body is then read so `bytes` reflects the real response.
    """
    context = None
    if scheme == "https":
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    else:
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        headers = {"Host": host_header} if host_header else {}
        started = time.perf_counter()
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        ttfb_ms = (time.perf_counter() - started) * 1000.0
        body = response.read()
        total_ms = (time.perf_counter() - started) * 1000.0
        return (response.status, len(body), ttfb_ms, total_ms,
                dict((key.lower(), value) for key, value in response.getheaders()))
    finally:
        connection.close()


def classify(status, ttfb_ms, slow_ms):
    """Sort a response into the bucket a report aggregates by, keeping tarpit behaviour visible.

    A response can be both `denied` and slow, and that combination is the interesting one: it means
    the client was answered from the tarpit rather than from the application.
    """
    if 200 <= status < 300:
        return "served"
    if 300 <= status < 400:
        return "redirect"
    if status == 403:
        return "denied"
    if status == 404:
        return "not_found"
    if 500 <= status < 600:
        return "error"
    return "other"


def scan(args):
    """Run the whole scan and return the report structure written to `--out`."""
    scheme, host, port = normalise_target(args.target)
    if args.paths_file:
        paths = paths_from_file(args.paths_file)
    elif args.from_host:
        paths = paths_from_host(args.from_host, args.docroot)
    else:
        raise SystemExit("webtree-scan: needs --paths-file or --from-host")
    paths = paths[:args.limit]
    insecure = args.insecure if args.insecure is not None else (scheme == "https")

    results, counts, fingerprints = [], {name: 0 for name in CLASSES}, {}
    for path in paths:
        try:
            status, size, ttfb_ms, total_ms, headers = request_one(
                scheme, host, port, path, args.host_header, args.timeout, insecure)
        except Exception as exc:  # noqa: BLE001 - a scan must report, not abort on one path
            results.append({"path": path, "error": "%s: %s" % (type(exc).__name__, exc)})
            counts["other"] += 1
            continue
        verdict = classify(status, ttfb_ms, args.slow_ms)
        counts[verdict] += 1
        for name in FINGERPRINT_HEADERS:
            if name in headers:
                fingerprints.setdefault(name, set()).add(headers[name])
        results.append({"path": path, "status": status, "bytes": size,
                        "ttfb_ms": round(ttfb_ms, 1), "total_ms": round(total_ms, 1),
                        "class": verdict, "drip": ttfb_ms >= args.slow_ms,
                        "server": headers.get("server", ""),
                        # A 3xx's whole value to a scanner is the Location: it names the canonical
                        # host and scheme even when the body is a stub, so it belongs in the record.
                        "location": headers.get("location", ""),
                        "x_powered_by": headers.get("x-powered-by", "")})

    return {"target": "%s://%s:%d" % (scheme, host, port),
            "host_header": args.host_header,
            "scanned_at": int(time.time()),
            "paths_requested": len(paths),
            "counts": counts,
            "fingerprints": dict((k, sorted(v)) for k, v in fingerprints.items()),
            "results": results}


def report(scan_result, stream):
    """Print the human-readable half of the output: summary first, then one line per path."""
    stream.write("target: %s  host_header: %s  paths: %d\n"
                 % (scan_result["target"], scan_result["host_header"] or "-",
                    scan_result["paths_requested"]))
    stream.write("counts: %s\n" % " ".join("%s=%d" % (name, scan_result["counts"][name])
                                           for name in CLASSES))
    for name, values in sorted(scan_result["fingerprints"].items()):
        stream.write("fingerprint %s: %s\n" % (name, ", ".join(values)))
    stream.write("%-44s %-6s %8s %9s %9s %s\n"
                 % ("path", "status", "bytes", "ttfb_ms", "total_ms", "flags"))
    for row in scan_result["results"]:
        if "error" in row:
            stream.write("%-44s %-6s %8s %9s %9s %s\n"
                         % (row["path"], "ERR", "-", "-", "-", row["error"]))
            continue
        flags = "drip" if row["drip"] else ""
        if row.get("location"):
            flags = (flags + " " if flags else "") + "-> " + row["location"]
        stream.write("%-44s %-6s %8d %9.1f %9.1f %s\n"
                     % (row["path"][:44], row["status"], row["bytes"],
                        row["ttfb_ms"], row["total_ms"], flags))


def main(argv=None):
    """Entry point: scan, print the report, and write the JSON document when asked."""
    args = parse_args(argv)
    scan_result = scan(args)
    report(scan_result, sys.stdout)
    if args.out:
        directory = os.path.dirname(os.path.abspath(args.out))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(args.out, "w") as handle:
            json.dump(scan_result, handle, indent=2, sort_keys=True)
            handle.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
