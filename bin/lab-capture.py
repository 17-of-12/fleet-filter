#!/usr/bin/env python3
"""Generate labelled access-log traffic against a lab victim, and record the labels.

Purpose
-------
A per-line model needs lines with labels, and hand-labelling by reading a log is guesswork that
bakes the labeller's assumptions into the training set. This script does the opposite: every request
it sends carries a **marker in its User-Agent**, so the label is written at emit time and recovered
exactly from the log line. No inference, no heuristics about what "looks like a scanner".

That matters beyond convenience: a training set labelled by a human's opinion of what a scanner looks
like teaches the model the human's opinion. A marker teaches it the difference between traffic the
project *chose* to send as benign and traffic it *chose* to send as hostile, and the log is the only
thing in between.

Design notes
------------
* **Benign traffic is real traffic.** The benign class is real requests to the real document root with
  a real browser User-Agent, not 404s with a friendly marker - a benign class made of failures teaches
  the model that benign means 404.
* **Exploit traffic is the actual CVE shape**, taken from `lab/README.md` and the CVE dossier, not a
  random path list. The traversal, `.env`, WordPress REST probe and h2c preface are the shapes the
  signatures claim to cover; if the model cannot separate those from benign, no ONNX file will help.
* **`ffuf` is optional and marked.** A brute-force sweep is the most useful scanner class and also the
  noisiest, so it is opt-in (`--ffuf`), bounded (`--ffuf-lines`), and marked with this script's own
  User-Agent rather than ffuf's default - a label must not depend on a tool's version string.
* **The log is read over SSH, read-only**, and lines without a marker are reported as `unlabelled`
  rather than dropped: "the capture produced lines nobody can attribute" is a finding, not a detail.

Usage
-----
    bin/lab-capture.py --host 10.20.0.226 --port 8081 --label-prefix ff-lab --state /var/lib/ff-httpd/2.4.49
    bin/lab-capture.py --host 10.20.0.226 --port 8081 --ffuf /tmp/ffuf --ffuf-lines 200
    bin/lab-capture.py --host 10.20.0.225 --port 8080 --out data/lab/traffic-2.4.66.jsonl

Exit code 0 when at least one line of each class was captured, 1 otherwise - a capture that produced
only benign traffic is a failure, because it cannot train a classifier.
"""

import argparse
import datetime
import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SSH_KEY = os.path.expanduser("~/.ssh/fleet_dispatch_key")

# The benign class: paths a visitor asks for, with a browser identity.
BENIGN_PATHS = ("/", "/index.html", "/index.html?utm_source=lab", "/index.html#top", "/favicon.ico")
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/131.0.0.0 Safari/537.36")

# The hostile class: the exact shapes the project's signatures claim to cover, plus the two live CVEs.
EXPLOIT_PATHS = (
    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
    "/.env",
    "/.git/config",
    "/wp-login.php",
    "/wp-json/batch/v1",
    "/xmlrpc.php",
    "/index.php?rest_route=/batch/v1",
    "/h2probe-bodyless",
)


def marker(label_prefix, klass):
    """The User-Agent marker that carries the label into the log, e.g. `ff-lab/benign`."""
    return "%s/%s" % (label_prefix, klass)


def fetch(url, user_agent, method="GET", body=None, timeout=10):
    """Send one request and return (status, bytes) - status 0 when the request never completed.

    A failed request is still traffic worth labelling, so an error is reported rather than raised:
    a scanner that dies mid-sweep leaves a half-sweep in the log, and that is realistic.
    """
    request = urllib.request.Request(url, method=method, data=body)
    request.add_header("User-Agent", user_agent)
    if body is not None:
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(4096)
    except urllib.error.HTTPError as error:
        return error.code, error.read(4096)
    except (urllib.error.URLError, OSError):
        return 0, b""


def h2c_preface(host, port, user_agent_marker, timeout=5):
    """Send the HTTP/2 connection preface on a cleartext port, the shape logged as method PRI.

    Written as raw bytes because no HTTP client library will send a preface without a negotiation
    first, and the preface is one of the project's measured signature shapes.
    """
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    try:
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.sendall(preface)
            connection.settimeout(timeout)
            try:
                return connection.recv(4096)
            except socket.timeout:
                return b""
    except OSError:
        return b""


def run_ffuf(ffuf_bin, url, label_prefix, lines):
    """Run a bounded ffuf sweep with this script's User-Agent so its lines are labelled exactly."""
    wordlist = os.path.join(REPO_ROOT, "lab", "wordlist.txt")
    argv = [ffuf_bin, "-u", url.rstrip("/") + "/FUZZ", "-w", wordlist,
            "-H", "User-Agent: %s" % marker(label_prefix, "scanner"),
            "-mc", "all", "-t", "4", "-s", "-o", "/dev/stdout", "-of", "json"]
    try:
        with open(os.devnull, "wb") as sink:
            subprocess.run(argv, stdout=sink, stderr=sink, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return True


def read_log(ssh_key, host, state_dir, user="operator"):
    """Read the victim's access log over SSH; raise RuntimeError when it cannot be read."""
    argv = ["ssh", "-i", ssh_key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            "-o", "LogLevel=ERROR", "%s@%s" % (user, host),
            "sudo -n cat %s/log/access_log" % state_dir]
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip())
    return proc.stdout.decode("utf-8", "replace").splitlines()


def label_line(line, label_prefix):
    """Recover the label from the line's User-Agent marker, or 'unlabelled'.

    The marker is `<prefix>/<class>`; anything else is reported as unlabelled so a capture that
    misses its own traffic is visible instead of silently rebalancing the classes.
    """
    for klass in ("benign", "exploit", "scanner"):
        if "%s/%s" % (label_prefix, klass) in line:
            return klass
    return "unlabelled"


def main(argv=None):
    """Send the probe matrix, pull the log, and write one JSON object per labelled line."""
    parser = argparse.ArgumentParser(description="Capture labelled access-log traffic from a lab victim")
    parser.add_argument("--host", default="10.20.0.226")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--scheme", default="http")
    parser.add_argument("--label-prefix", default="ff-lab")
    parser.add_argument("--state", default="/var/lib/ff-httpd/2.4.49", help="victim state dir on the host")
    parser.add_argument("--ssh-key", default=DEFAULT_SSH_KEY)
    parser.add_argument("--out", default="")
    parser.add_argument("--ffuf", default="", help="path to the ffuf binary to add a scanner class")
    parser.add_argument("--ffuf-lines", type=int, default=60)
    args = parser.parse_args(argv)

    base = "%s://%s:%d" % (args.scheme, args.host, args.port)
    started = datetime.datetime.now(datetime.timezone.utc)

    for path in BENIGN_PATHS:
        fetch(base + path, "%s %s" % (BROWSER_UA, marker(args.label_prefix, "benign")))
    for path in EXPLOIT_PATHS[:6]:
        fetch(base + path, "curl/8.18.0 %s" % marker(args.label_prefix, "exploit"))
    fetch(base + EXPLOIT_PATHS[0], "curl/8.18.0 %s" % marker(args.label_prefix, "exploit"),
          method="POST", body=b"echo Content-Type: text/plain; echo; id")
    h2c_preface(args.host, args.port, marker(args.label_prefix, "exploit"))
    if args.ffuf:
        run_ffuf(args.ffuf, base, args.label_prefix, args.ffuf_lines)

    try:
        lines = read_log(args.ssh_key, args.host, args.state)
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        sys.stderr.write("log read failed: %s\n" % error)
        return 2

    rows = []
    counts = {}
    for line in lines:
        klass = label_line(line, args.label_prefix)
        counts[klass] = counts.get(klass, 0) + 1
        rows.append({"line": line, "label": klass, "captured_at": started.isoformat(),
                     "target": "%s:%d" % (args.host, args.port), "state": args.state})

    destination = args.out or os.path.join(
        REPO_ROOT, "data", "lab", "traffic-%s-%d-%s.jsonl"
        % (args.host, args.port, started.strftime("%Y%m%dT%H%M%SZ")))
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    with open(destination, "w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    print("captured %d lines -> %s" % (len(rows), destination))
    for klass in sorted(counts):
        print("  %-11s %d" % (klass, counts[klass]))

    wanted = ("benign", "exploit")
    return 0 if all(counts.get(name) for name in wanted) else 1


if __name__ == "__main__":
    sys.exit(main())
