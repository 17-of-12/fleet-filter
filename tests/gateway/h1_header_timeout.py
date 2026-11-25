#!/usr/bin/env python3
"""Measure how long the Stage 2 gateway holds an HTTP/1.1 connection whose headers never finish.

Purpose: prove the `[limits] header_read_timeout_secs` control (Bundle O6) is enforced rather than
merely declared. A client that sends a request line plus one header and never terminates the
header block used to cost the gateway a socket for as long as it liked; with the control armed the
connection must close after the configured number of seconds.

The client deliberately does not negotiate ALPN, so the server falls back to HTTP/1.1 - the only
protocol path on which hyper applies `header_read_timeout`, and therefore the path an earlier
revision of the gateway refused to configure at all.

Usage:
    python3 h1_header_timeout.py [--host 198.51.100.111] [--port 8443] [--timeout 90]

Output is one JSON object: seconds the connection was held, bytes returned before the close, and
the negotiated ALPN protocol. Python 3.6 compatible (the OL8 host interpreter is 3.6.8).
"""

import argparse
import json
import socket
import ssl
import time


def measure(host, port, timeout):
    """Connect over TLS, send an incomplete HTTP/1.1 header block, and time until the server closes.

    Returns (seconds_held, bytes_returned, alpn). `alpn` is None when the server does not select a
    protocol, which is the expected case and what forces the HTTP/1.1 code path under test.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    started = time.time()
    received = 0
    alpn = None
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        tls = context.wrap_socket(raw, server_hostname=host)
        try:
            tls.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode("utf-8") + b"\r\n")
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                received += len(chunk)
            alpn = tls.selected_alpn_protocol()
        finally:
            tls.close()
    finally:
        raw.close()
    return round(time.time() - started, 2), received, alpn


def main():
    """Parse arguments, run one measurement, and print the result as JSON."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="198.51.100.111")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument(
        "--timeout",
        type=int,
        default=90,
        help="client-side socket timeout; must exceed the gateway's configured header read timeout",
    )
    args = parser.parse_args()
    seconds, bytes_returned, alpn = measure(args.host, args.port, args.timeout)
    print(
        json.dumps(
            {
                "seconds_held": seconds,
                "bytes_returned": bytes_returned,
                "alpn": alpn if alpn else "none",
            }
        )
    )


if __name__ == "__main__":
    main()
