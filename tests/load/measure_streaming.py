#!/usr/bin/env python3
"""B8 - measure the reference responder's streaming behaviour at the client.

Answers three questions that a single `time_total` cannot: when does the first byte arrive, how long
does the whole response take, and how does the body actually arrive (chunk count, chunk sizes, and the
gaps between chunks). The last one matters because the tarpit's whole product is *time spent by the
client*, and a responder that sends the body in one burst after a 5 s pause behaves very differently -
from the attacker's side - than one that drips it, even though both report the same total duration.

Usage:
    python3 measure_streaming.py --host 127.0.0.1 --port 8081 --path /ai.html --samples 3
"""

from __future__ import print_function

import argparse
import http.client
import json
import socket
import statistics
import sys
import time

BUFSIZE = 4096


def probe_once(host, port, path, timeout):
    """Issue one GET and return timing plus the raw chunk arrival trace.

    `read1` is used instead of `read` so each return corresponds to what the socket actually
    delivered, which is the only way to observe chunking rather than the client's buffering.
    """
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    trace = []
    started = time.monotonic()
    conn.request("GET", path, headers={"User-Agent": "fleet-filter-b8/1.0", "Accept": "*/*"})
    response = conn.getresponse()
    ttfb = time.monotonic() - started
    body = bytearray()
    while True:
        # HTTPResponse.read1 dechunks as it goes and returns whatever the socket delivered, which is
        # what "observed chunk arrival" means here; falling back to read() would hide the chunking.
        chunk = response.read1(BUFSIZE) if hasattr(response, "read1") else response.read(BUFSIZE)
        if not chunk:
            break
        body.extend(chunk)
        trace.append((round(time.monotonic() - started, 4), len(chunk)))
        if len(body) > 8 * 1024 * 1024:  # safety valve against an unbounded stream
            break
    total = time.monotonic() - started
    length = response.getheader("Content-Length")
    transfer = response.getheader("Transfer-Encoding")
    conn.close()
    return {
        "status": response.status,
        "content_length": length,
        "transfer_encoding": transfer,
        "ttfb_s": round(ttfb, 4),
        "total_s": round(total, 4),
        "bytes": len(body),
        "chunks": len(trace),
        "chunk_sizes": [size for _, size in trace][:20],
        "trace_head": trace[:6],
    }


def stats(values):
    """min / median / max as strings ([] -> n/a)."""
    if not values:
        return "n/a"
    return "%.3f / %.3f / %.3f" % (min(values), statistics.median(values), max(values))


def main():
    """Parse arguments, run the samples, print the report."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--path", default="/")
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--json", action="store_true", help="emit raw JSON instead of markdown")
    args = parser.parse_args()

    results = []
    for _ in range(args.samples):
        try:
            results.append(probe_once(args.host, args.port, args.path, args.timeout))
        except (socket.timeout, OSError, http.client.HTTPException) as exc:
            results.append({"error": "%s: %s" % (type(exc).__name__, exc)})

    if args.json:
        print(json.dumps(results, indent=1))
        return 0 if all("error" not in r for r in results) else 1

    ok = [r for r in results if "error" not in r]
    print("target: http://%s:%d%s  samples: %d  errors: %d"
          % (args.host, args.port, args.path, args.samples, len(results) - len(ok)))
    if not ok:
        print("no successful sample; raw results: %s" % json.dumps(results))
        return 1
    print()
    print("| metric | min / median / max (s) |")
    print("|---|---|")
    print("| time to first byte | %s |" % stats([r["ttfb_s"] for r in ok]))
    print("| total duration | %s |" % stats([r["total_s"] for r in ok]))
    print()
    print("| sample | status | declared length | transfer-encoding | bytes read | chunks | first chunks |")
    print("|---|---|---|---|---|---|---|")
    for index, r in enumerate(ok, 1):
        print("| %d | %s | %s | %s | %d | %d | %s |" % (
            index, r["status"], r["content_length"] or "-", r["transfer_encoding"] or "-",
            r["bytes"], r["chunks"], ", ".join(str(s) for s in r["chunk_sizes"][:6])))
    for index, r in enumerate(ok, 1):
        if r["trace_head"]:
            print("sample %d arrival trace (s, bytes): %s" % (index, r["trace_head"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
