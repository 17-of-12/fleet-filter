#!/usr/bin/env python3
"""Unit checks for bin/render-gateway-detection.py (code-review finding PTN-05).

The renderer is what makes the signature store the single source of truth for the Stage 2
gateway's matcher set, so these checks cover the two ways it could be wrong in practice:
deriving a prefix the store's pattern does not actually describe, and silently dropping a
variant the gateway cannot express instead of reporting it.
"""

from __future__ import print_function

import importlib.util
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(ROOT, "bin", "render-gateway-detection.py")
STORE = os.path.join(ROOT, "controller", "signatures", "signatures.yaml")

spec = importlib.util.spec_from_file_location("render_gateway_detection", SCRIPT)
rgd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rgd)

PASS = 0
FAIL = 0


def check(condition, label):
    """Record one assertion and print it, so the run reports every failure not just the first."""
    global PASS, FAIL
    if condition:
        PASS += 1
        print("ok   %s" % label)
    else:
        FAIL += 1
        print("FAIL %s" % label)
    return condition


# --- literal_prefix: the derivation that replaces the hand-written `prefixes` list ------------------
check(rgd.literal_prefix("^/h2probe-[0-9]{1,8}$") == "/h2probe-",
      "a digit-class pattern yields its literal prefix")
check(rgd.literal_prefix("^/wp-json/batch/v1$") == "/wp-json/batch/v1",
      "a plain anchored path yields the whole path")
check(rgd.literal_prefix(r"^(?:/|/index\.php)\?rest_route=/batch/v1$") is None,
      "a leading alternation has no single literal, so it yields None")
check(rgd.literal_prefix("^/{2,}wp-json/batch/v1$") is None,
      "a quantified slash would widen to `/`, which is refused rather than shipped")
check(rgd.literal_prefix("/no-anchor.php") is None,
      "an unanchored pattern yields None (a prefix needs an anchored start)")
check(rgd.literal_prefix(r"^/a\?b$") == "/a?b",
      "an escaped literal is unfolded into the character it matches")
check(rgd.literal_prefix("") is None and rgd.literal_prefix("^") is None,
      "empty and anchor-only patterns yield None")

# --- classify_variant: every state the renderer can report ------------------------------------------
check(rgd.classify_variant("CVE-1", {"name": "off", "enabled": False,
                                     "disabled_reason": "not ready",
                                     "match": {"uri_regex": "^/x$"}})[1] == "disabled",
      "an enabled:false variant is reported disabled, not dropped")
check(rgd.classify_variant("CVE-1", {"name": "logonly", "tier": [2],
                                     "match": {"uri_regex": "^/x$"}})[1] == "log-only",
      "a tier-2-only variant is reported log-only")
check(rgd.classify_variant("CVE-1", {"name": "no_uri", "tier": [1],
                                     "match": {"method": ["PRI"]}})[1] == "unsupported",
      "a variant with no uri_regex is unsupported (the gateway matches URI prefixes only)")
check(rgd.classify_variant("CVE-1", {"name": "ok", "tier": [1],
                                     "match": {"uri_regex": "^/x$"}})[:2] == ("CVE-1:ok", "enforced"),
      "a plain variant is enforced under its ID:variant reference")
check(rgd.classify_variant("CVE-1", {"name": "bad", "tier": [1],
                                     "match": {"uri_regex": "^/x$"},
                                     "gateway_prefixes": ["^/y$"]})[1] == "unsupported",
      "a declared prefix that is a pasted regex is refused")
check(rgd.classify_variant("CVE-1", {"name": "lie", "tier": [1],
                                     "match": {"uri_regex": "^/x$"},
                                     "gateway_prefixes": ["/not-a-fixture"]})[1] == "unsupported",
      "a declared prefix that matches no positive fixture is refused (the claim is checked)")
check(rgd.classify_variant("CVE-1", {"name": "declared", "tier": [1],
                                     "match": {"uri_regex": r"^(?:/a|/b)\?c$"},
                                     "gateway_prefixes": ["/a?c"],
                                     "tests": {"positive": ["/a?c", "/b?c"]}})[1] == "enforced",
      "a declared prefix that does prefix a fixture is accepted")

# --- render against the real store --------------------------------------------------------------------
store_text = open(STORE).read()
rendered, enforced, rows = rgd.render(store_text, STORE)
check("store_sha256" in rendered, "the render records the store digest it was generated from")
check(all(ref in rendered for ref, _, _, _ in rows),
      "every variant in the store is named in the render, enforced or not")
for prefix in (p for _, prefixes in enforced for p in prefixes):
    check('"%s"' % prefix in rendered, "enforced prefix is present: %s" % prefix)
check(sum(1 for line in rendered.split("\n") if line.strip() == "[detection]") == 1,
      "exactly one [detection] table header is emitted")

# --- the CLI contract ---------------------------------------------------------------------------------
work = tempfile.mkdtemp(prefix="pt-render-gw-")
out = os.path.join(work, "detection.toml")
proc = subprocess.run([sys.executable, SCRIPT, "--store", STORE, "--out", out],
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
check(proc.returncode == 0 and os.path.isfile(out), "the CLI writes the file it was asked to write")


def without_stamp(text):
    """Drop the `generated_at:` line so two renders made at different times can be compared.

    `render()` stamps the current second into its header, so comparing a render made here with one
    made by the subprocess below compares two clocks, not two strings. That comparison is only
    equal when both land in the same second - measured 2026-11-24 as roughly one failure in six
    runs - which makes a green gate a coin toss rather than a claim about the CLI.
    """
    return "\n".join(line for line in text.split("\n")
                     if "#   generated_at: " not in line)


check(without_stamp(open(out).read()) == without_stamp(rendered),
      "the CLI writes exactly what render() produced (modulo the generation timestamp)")

empty = os.path.join(work, "empty.yaml")
with open(empty, "w") as handle:
    handle.write("signatures: []\n")
proc = subprocess.run([sys.executable, SCRIPT, "--store", empty, "--out", out],
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
check(proc.returncode != 0, "an empty store is a refusal, not an empty file written over a good one")

missing = os.path.join(work, "nope.yaml")
proc = subprocess.run([sys.executable, SCRIPT, "--store", missing, "--out", out],
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
check(proc.returncode != 0, "a missing store path exits non-zero")

print("\ntest_render_gateway_detection.py: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
