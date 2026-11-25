#!/usr/bin/env python3
"""Tests for controller/sigtest.py (E10) - log replay of the signature store.

Covers the parser (every Apache log format the project emits), the evaluator's three-way verdict, and
the two failure modes the first implementation shipped with: a disabled variant matching every request
because it has no `match` block, and the allowlist not being subtracted from the blast radius.

Runs under Python 3.9 and 3.12; skips cleanly when PyYAML is unavailable, matching the convention set
by tests/unit/test_render_rules.py.
"""

from __future__ import print_function

import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

try:
    import yaml  # noqa: F401
except ImportError:
    print("SKIP test_sigtest.py: PyYAML unavailable for %s" % sys.version.split()[0])
    raise SystemExit(0)

SPEC = importlib.util.spec_from_file_location("sigtest", os.path.join(ROOT, "controller", "sigtest.py"))
sigtest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sigtest)

PASS = 0
FAIL = 0


def check(condition, label):
    """Record one assertion."""
    global PASS, FAIL
    if condition:
        PASS += 1
        print("ok   %s" % label)
    else:
        FAIL += 1
        print("FAIL %s" % label)


TARPITEXT = ('10.30.72.218 - - [12/Nov/2026:17:57:46 -0500] "GET / HTTP/2.0" 403 123 "-" "-" '
             'ct=application/x-www-form-urlencoded cl=0 ho=localhost')
COMBINED = ('10.0.0.5 - - [12/Nov/2026:18:00:00 -0500] "GET /h2probe-12075394 HTTP/1.1" 404 196 '
            '"-" "curl/7.61.1"')
GATEWAY = ('198.51.100.110 - - [14/Nov/2026:19:59:13 -0500] "GET /ai.html HTTP/1.1" 200 754 "-" '
           '"curl/7.61.1" reqid=- xff=-')
COMMON = '10.0.0.9 - - [12/Nov/2026:18:05:00 -0500] "GET /index.html HTTP/1.1" 200 512'
MALFORMED = 'not a log line at all'

# ---- parser ---------------------------------------------------------------------------------------
entry = sigtest.parse_line(TARPITEXT)
check(entry is not None, "parses the project's `tarpitext` format")
check(entry and entry["client"] == "10.30.72.218", "client address captured from %h")
check(entry and entry["method"] == "GET" and entry["path"] == "/" and entry["protocol"] == "HTTP/2.0",
      "method/path/protocol split out of the request line")
check(entry and entry["extras"].get("ct") == "application/x-www-form-urlencoded"
      and entry["extras"].get("cl") == "0" and entry["extras"].get("ho") == "localhost",
      "extended header fields (ct/cl/ho) captured generically")
check(entry and entry["status"] == "403", "status captured")

combined_entry = sigtest.parse_line(COMBINED)
check(combined_entry and combined_entry["path"] == "/h2probe-12075394"
      and combined_entry["extras"] == {},
      "parses stock `combined` and reports no header extras")
check(sigtest.parse_line(GATEWAY)["extras"].get("xff") == "-",
      "parses the gateway backend format (reqid=/xff=) without special-casing it")
check(sigtest.parse_line(COMMON) and sigtest.parse_line(COMMON)["formats"] == "common",
      "parses `common` (no referer/user-agent) and labels the format")
check(sigtest.parse_line(MALFORMED) is None, "rejects a line that is not a request record")
check(sigtest.parse_time("12/Nov/2026:17:57:46 -0500") is not None
      and sigtest.parse_time("garbage") is None, "timestamp parses, and bad timestamps return None")

# ---- evaluator ------------------------------------------------------------------------------------
probe_variant = {"uri_regex": r"^/h2probe-[0-9]{1,8}$"}
check(sigtest.evaluate(probe_variant, combined_entry) is True, "probe_path matches the probe URL")
check(sigtest.evaluate(probe_variant, entry) is False, "probe_path does not match `/`")

bodyless = {"method": "GET", "protocol": "h2", "content_type_present": True, "content_length_in": ["-", "0", ""]}
check(sigtest.evaluate(bodyless, entry) is True, "bodyless_ct matches the measured PoC request (h2, ct set, cl 0)")
check(sigtest.evaluate(bodyless, combined_entry) is None,
      "a header-dependent variant is unevaluable on a log without header capture, not a silent non-match")

check(sigtest.evaluate({}, entry) is None,
      "an empty match block is unevaluable rather than matching everything (the framing_only_shapes bug)")
check(sigtest.evaluate({"method": "CONNECT", "protocol": "h2"}, entry) is False,
      "method mismatch returns False")
check(sigtest.evaluate({"uri_regex": "^(a+)+$"}, entry) is not True,
      "a pathological regex does not raise past the guard")

# ---- end-to-end against a store and a log ----------------------------------------------------------
with tempfile.TemporaryDirectory() as work:
    store_path = os.path.join(work, "signatures.yaml")
    with open(store_path, "w") as handle:
        yaml.safe_dump({
            "signatures": [{
                "id": "CVE-TEST",
                "variants": [
                    {"name": "probe_path", "match": {"uri_regex": r"^/h2probe-[0-9]{1,8}$"},
                     "response_profile": "slow_404_app_shaped"},
                    {"name": "framing_only_shapes", "enabled": False,
                     "disabled_reason": "needs an h2-aware engine", "shapes": ["body_ct"]},
                ],
            }],
        }, handle)
    probe2 = ('198.51.100.61 - - [13/Nov/2026:09:00:00 -0500] "GET /h2probe-7777777 HTTP/1.1" 404 196 '
              '"-" "curl/7.61.1"')
    log_path = os.path.join(work, "access_log")
    with open(log_path, "w") as handle:
        handle.write("\n".join([COMBINED, probe2, TARPITEXT, GATEWAY, MALFORMED]) + "\n")
    allow_path = os.path.join(work, "allowlist")
    with open(allow_path, "w") as handle:
        handle.write("# comment\n10.0.0.5 0\n")

    report = sigtest.analyse([log_path], store_path, allow_path, max_examples=2)
    check(report["files"][0]["parsed"] == 4 and report["files"][0]["unparsed"] == 1,
          "counts 4 parsed request lines and 1 unparsed line")
    variants = report["files"][0]["variants"]
    check("CVE-TEST/probe_path" in variants and variants["CVE-TEST/probe_path"]["matches"] == 2,
          "the matching variant is reported with its count (two probe requests in the fixture)")
    check("CVE-TEST/framing_only_shapes" not in variants
          and report["files"][0]["disabled_variants"].get("CVE-TEST/framing_only_shapes"),
          "a disabled variant is reported as disabled instead of being evaluated")
    check(report["allowlist_suppressed"] == [["10.0.0.5", 1]],
          "allowlisted addresses are subtracted from the would-quarantine list and reported separately")
    check(report["would_quarantine"] == [["198.51.100.61", 1]],
          "non-allowlisted matching addresses are the reported blast radius")
    text = sigtest.render_text(report)
    check("MATCH CVE-TEST/probe_path" in text and "disabled CVE-TEST/framing_only_shapes" in text,
          "the text report renders both the match and the disabled variant")

print("test_sigtest.py: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
