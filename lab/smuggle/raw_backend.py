#!/usr/bin/env python3
"""A deliberately lenient HTTP/1.1 backend, so request smuggling can be observed rather than argued.

Purpose
-------
Smuggling is a disagreement between two parsers about where a request ends. To demonstrate it you
need a backend that parses like the vulnerable ones do - honouring `Content-Length` and ignoring
`Transfer-Encoding` when both are present - and a log of the exact bytes it received. Then "the
attack worked" and "the attack did not arrive" are both facts on disk, not interpretations.

This is a test fixture, not a product: it exists so a front end can be measured against a parser that
disagrees with it. The bytes it captures are the evidence.

Design notes
------------
* **Raw sockets, not http.server.** The question is what arrived on the wire, and a framework's parser
  answers a different question (what it decided the bytes meant). Every connection is read, logged
  verbatim, and answered with a single marker line.
* **Lenient by design, and labelled as such.** `Content-Length` wins over `Transfer-Encoding`, which
  is what several real servers did and what makes the classic CL.TE desync possible. A strict backend
  would return 400 and the experiment would prove nothing about the proxy.
* **One log line per connection**, with the request lines it contains counted and printed, so a
  smuggled request appears as a second request line inside one connection.

Usage
-----
    lab/smuggle/raw_backend.py --port 9100 --log /tmp/smuggle-backend.log
"""

import argparse
import datetime
import socket
import sys
import threading


def handle(connection, log_path, index):
    """Read one connection to quiescence and record the bytes, plus the request lines inside them."""
    connection.settimeout(1.0)
    chunks = []
    try:
        while True:
            data = connection.recv(65536)
            if not data:
                break
            chunks.append(data)
            if sum(len(chunk) for chunk in chunks) > 1_000_000:
                break
    except (socket.timeout, OSError):
        pass
    payload = b"".join(chunks)

    request_lines = [line for line in payload.split(b"\r\n") if line.startswith((b"GET ", b"POST "))]
    with open(log_path, "a") as handle:
        handle.write("%s conn=%d bytes=%d request_lines=%d\n"
                     % (datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        index, len(payload), len(request_lines)))
        for line in request_lines:
            handle.write("    %r\n" % line)
        handle.write("    raw=%r\n" % payload[:600])
    try:
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    except OSError:
        pass
    connection.close()


def main(argv=None):
    """Listen, log every connection, and answer with a marker."""
    parser = argparse.ArgumentParser(description="Lenient raw HTTP backend for smuggling tests")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9100)
    parser.add_argument("--log", default="/tmp/smuggle-backend.log")
    args = parser.parse_args(argv)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.bind, args.port))
        listener.listen(32)
        sys.stderr.write("lenient backend on %s:%d, log %s\n" % (args.bind, args.port, args.log))
        index = 0
        while True:
            connection, _ = listener.accept()
            index += 1
            threading.Thread(target=handle, args=(connection, args.log, index), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
