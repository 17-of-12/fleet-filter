#!/usr/bin/env python3
"""Checks for the lab inventory's parsers and its intent-vs-reality comparison.

Purpose
-------
`bin/lab-inventory.py` is the project's answer to "what is running where", and its exit code is used
as a gate. A gate whose parser silently drops a line reports a clean lab that is not clean, which is
the same class of failure as a signature that matches nothing. So the parsing and the comparison are
exercised here against captured text, with no lab required (rule 17: the fixture is the oracle).

The `ss` and `podman` outputs below are the shapes measured on ff-apache01/ff-apache02 on
2026-11-24, trimmed to what the parser reads.

Runs under Python 3.6+ with no third-party modules.
"""

from __future__ import print_function

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SCRIPT = os.path.join(ROOT, "bin", "lab-inventory.py")

SPEC = importlib.util.spec_from_file_location("lab_inventory", SCRIPT)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)

PASS = 0
FAIL = 0


def check(condition, label):
    """Record one assertion, printing ok/FAIL for the shell harness."""
    global PASS, FAIL
    if condition:
        PASS += 1
        print("ok   %s" % label)
    else:
        FAIL += 1
        print("FAIL %s" % label)


# --- parsers ----------------------------------------------------------------------------------
containers = lab.parse_containers(
    "ff-httpd-2.4.62|localhost/ff-httpd:2.4.62|Up 20 minutes\n"
    "ff-httpd-2.4.49|localhost/ff-httpd:2.4.49|Up 20 minutes\n"
    "garbage line without pipes\n"
)
check(len(containers) == 2, "two container lines parse and the malformed line is skipped")
check(containers["ff-httpd-2.4.49"]["image"] == "localhost/ff-httpd:2.4.49",
      "the image is carried verbatim, which is what the drift check compares")

images = lab.parse_images(
    "localhost/ff-httpd:2.4.66|sha256:47c8f39f\n"
    "localhost/ff-httpd:2.4.49|<none>\n"
)
check(images["localhost/ff-httpd:2.4.66"] == "sha256:47c8f39f", "an image digest is parsed")
check(images["localhost/ff-httpd:2.4.49"] == "<none>", "an unset digest is kept, not dropped")

listeners = lab.parse_listeners(
    "LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:*\n"
    "LISTEN 0 4096 0.0.0.0:8081 0.0.0.0:*\n"
    "LISTEN 0 4096 [::]:8443 [::]:*\n"
    "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
    "LISTEN 0 4096 *:9000 *:*\n"
    "short line\n"
)
check(listeners == [22, 8080, 8081, 8443, 9000],
      "every address form yields its port and a short line does not crash the parse")

# --- comparison -------------------------------------------------------------------------------
host = {
    "name": "ff-apache02",
    "ip": "10.20.0.226",
    "expected": [
        {"container": "ff-httpd-2.4.62", "image": "localhost/ff-httpd:2.4.62", "ports": [8080, 8443]},
        {"container": "ff-httpd-2.4.49", "image": "localhost/ff-httpd:2.4.49", "ports": [8081, 8444]},
    ],
}
observed = {
    "containers": {
        "ff-httpd-2.4.62": {"image": "localhost/ff-httpd:2.4.62", "status": "Up"},
        "ff-httpd-2.4.49": {"image": "localhost/ff-httpd:2.4.49", "status": "Up"},
    },
    "ports": [22, 8080, 8081, 8443, 8444],
}
check(lab.compare(host, observed) == [], "a host matching its declaration reports no drift")

missing = {"containers": {"ff-httpd-2.4.62": {"image": "localhost/ff-httpd:2.4.62", "status": "Up"}},
           "ports": [8080, 8443, 8081, 8444]}
findings = lab.compare(host, missing)
check(any("ff-httpd-2.4.49 is not running" in finding for finding in findings),
      "a declared container that is not running is drift")

wrong_image = {"containers": {
    "ff-httpd-2.4.62": {"image": "localhost/ff-httpd:2.4.62", "status": "Up"},
    "ff-httpd-2.4.49": {"image": "localhost/ff-httpd:2.4.66", "status": "Up"},
}, "ports": [8080, 8443, 8081, 8444]}
findings = lab.compare(host, wrong_image)
check(any("runs localhost/ff-httpd:2.4.66, declared localhost/ff-httpd:2.4.49" in finding
          for finding in findings),
      "a container running the wrong version is drift - the CVE would be the wrong one")

port_missing = {"containers": dict(observed["containers"]), "ports": [8080, 8443, 8081]}
findings = lab.compare(host, port_missing)
check(any("declares port 8444, nothing listening" in finding for finding in findings),
      "a declared listener that is not listening is drift")

# --- rendering and exit semantics -------------------------------------------------------------
inventory = {"schema": 1, "hosts": [
    {"name": "ff-apache01", "ip": "10.20.0.225", "role": "victim",
     "observed": {"error": "", "containers": {"ff-httpd-2.4.66": {"image": "localhost/ff-httpd:2.4.66",
                                                                  "status": "Up"}},
                  "images": {}, "ports": [8080, 8443]},
     "findings": []},
    {"name": "ff-control01", "ip": "10.20.0.205", "role": "control",
     "observed": {"error": "ssh: timed out", "containers": {}, "images": {}, "ports": []},
     "findings": ["ff-control01: unreadable (ssh: timed out)"]},
]}
table = lab.render(inventory)
check("ff-httpd-2.4.66" in table and "ports=8080,8443" in table, "the table shows container and ports")
check("UNREADABLE: ssh: timed out" in table, "an unreachable host is visible, not rendered as clean")
check("drift: 1 finding(s)" in table, "the summary counts findings")

print("\ntest_lab_inventory.py: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
