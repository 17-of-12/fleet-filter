#!/usr/bin/env python3
"""
Signature store test harness - Fleet-Filter E16.

Validates controller/signatures/signatures.yaml:
  1. every regex in the store compiles;
  2. every `positive` string matches its own variant's pattern;
  3. every `negative` string does NOT match its own variant's pattern;
  4. every variant that targets a header field carries log-line fixtures in the
     declared extended format (section 7 rule: a header-targeting signature on a
     host without header logging is a refusal, not a silent no-op);
  5. any `apache_inline` block's RewriteCond regex compiles and agrees with
     `match.uri_regex` where both exist (catches drift between the store and the
     generated Apache ruleset).

Exit status: 0 = all checks pass, 1 = at least one failure.
"""

import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML is required (python3 -m pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / "controller" / "signatures" / "signatures.yaml"

# Apache combined format plus the header fields the store depends on.
LOG_LINE = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'(?P<request>"(?P<method>[A-Z]+) (?P<uri>[^"]*?) (?P<proto>[^"]*)"|\S+) '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<useragent>[^"]*)"'
    r'(?:\s+ct=(?P<ctype>\S+))?(?:\s+cl=(?P<clen>\S+))?(?:\s+ho=(?P<host>\S+))?\s*$'
)

PROTO_NAME = {"HTTP/2.0": "h2", "HTTP/2": "h2", "HTTP/1.1": "http1", "HTTP/1.0": "http1"}

failures = []
checks = 0


def check(label, condition, detail=""):
    """Record one assertion and remember the failure text.

    Accumulates instead of raising so one run surfaces every broken signature; the caller
    prints the total and sets the exit code from `failures`.
    """
    global checks
    checks += 1
    if not condition:
        failures.append(f"{label}: {detail}")
    return condition


def compile_regex(label, pattern):
    """Compile a stored pattern, or fail the suite naming the pattern that broke.

    Compiling separately from matching matters: an uncompileable regex would otherwise
    surface as a silent miss on every fixture, and a ReDoS-shaped pattern is worth finding
    before it ever reaches a request path.
    """
    try:
        return re.compile(pattern)
    except re.error as exc:
        check(label, False, f"regex {pattern!r} does not compile: {exc}")
        return None


def parse_log_line(line):
    """Return a dict for a line in the declared format, else None."""
    match = LOG_LINE.match(line)
    return match.groupdict() if match else None


def evaluate(variant, raw):
    """
    Decide whether `raw` (a bare URI, a bare header name, or a full log line)
    is a hit for `variant`. Returns (hit, reason).
    """
    match = variant.get("match", {})
    record = parse_log_line(raw)

    # Bare header name test (header_regex variants).
    if record is None and "header_regex" in match and " " not in raw and "[" not in raw:
        rx = compile_regex(f"{variant['name']}.header_regex", match["header_regex"])
        if rx is None:
            return False, "uncompilable"
        return bool(rx.fullmatch(raw)), "header_regex"

    # Bare URI test (uri_regex variants).
    if record is None and "uri_regex" in match and " " not in raw:
        rx = compile_regex(f"{variant['name']}.uri_regex", match["uri_regex"])
        if rx is None:
            return False, "uncompilable"
        return bool(rx.fullmatch(raw)), "uri_regex"

    if record is None:
        return False, "input is neither a bare URI/header nor a parseable log line"

    # Full log line: evaluate every declared field constraint.
    reasons = []
    ok = True

    if "uri_regex" in match:
        rx = compile_regex(f"{variant['name']}.uri_regex", match["uri_regex"])
        field_ok = bool(rx and rx.fullmatch(record["uri"] or ""))
        reasons.append(f"uri_regex vs {record['uri']!r}")
        ok = ok and field_ok

    if "header_regex" in match:
        rx = compile_regex(f"{variant['name']}.header_regex", match["header_regex"])
        header = match.get("header", "").lower()
        value = record.get({"content-type": "ctype", "content-length": "clen",
                            "host": "host"}.get(header, "host")) or "-"
        field_ok = bool(rx and rx.fullmatch(value))
        reasons.append(f"header_regex vs {header}={value!r}")
        ok = ok and field_ok

    if "protocol" in match:
        proto = PROTO_NAME.get(record["proto"] or "", record["proto"] or "")
        field_ok = proto in set(match["protocol"])
        reasons.append(f"protocol {record['proto']!r} -> {proto!r}")
        ok = ok and field_ok

    if "method" in match:
        field_ok = (record["method"] or "").upper() in {m.upper() for m in match["method"]}
        reasons.append(f"method {record['method']!r}")
        ok = ok and field_ok

    if "content_type_present" in match:
        value = record["ctype"] or "-"
        present = value != "-" and value != ""
        field_ok = present == bool(match["content_type_present"])
        reasons.append(f"content-type {value!r} present={present}")
        ok = ok and field_ok

    if "content_length_in" in match:
        value = record["clen"] or "-"
        field_ok = value in set(match["content_length_in"])
        reasons.append(f"content-length {value!r} not in {sorted(match['content_length_in'])}")
        ok = ok and field_ok

    if not reasons:
        return False, "log line parsed but variant declares no log-evaluable field"
    return ok, "; ".join(reasons)


def check_fixture(kind, variant, raw):
    """Assert one fixture against one variant, in the direction the fixture's kind implies.

    `kind` decides the expectation (`*_positive` must hit, `*_negative` must miss), so the
    same call shape covers both halves of the pair. A variant with only positive fixtures
    proves nothing about false positives, which is why both directions are required here.
    """
    hit, reason = evaluate(variant, raw)
    expect_hit = kind.endswith("positive")
    expectation = "expected hit, got miss" if expect_hit else "expected miss, got hit"
    check(f"{variant['id']}/{variant['name']} [{kind}] {raw}",
          hit == expect_hit, f"{expectation} ({reason})")


def main():
    """Load the signature store and run every variant's fixtures through the evaluator.

    The store is the thing under test, not the fixtures: this proves the stored regexes
    compile and match the recorded real Apache output, and that the negative fixtures do
    not match. Exits non-zero if any check failed or the store is missing.
    """
    if not STORE.exists():
        print(f"missing signature store: {STORE}", file=sys.stderr)
        return 1

    store = yaml.safe_load(STORE.read_text())
    signatures = store["signatures"]
    print(f"store: {STORE}")
    print(f"signatures: {len(signatures)}\n")

    for sig in signatures:
        print(f"== {sig['id']} ({sig.get('class')}) ttl={sig.get('ttl')} review_by={sig.get('review_by')}")
        for variant in sig.get("variants", []):
            variant.setdefault("id", sig["id"])
            tests = variant.get("tests", {})
            state = "enabled" if variant.get("enabled", True) else "disabled"
            print(f"  - {variant['name']} [{state}] tiers={variant.get('tier')}")

            for raw in tests.get("positive", []):
                check_fixture("positive", variant, raw)
            for raw in tests.get("negative", []):
                check_fixture("negative", variant, raw)
            for raw in tests.get("log_positive", []):
                check_fixture("log-positive", variant, raw)
            for raw in tests.get("log_negative", []):
                check_fixture("log-negative", variant, raw)

            # Section 7 rule: a header-targeting variant must ship a fixture that
            # proves the field is actually observable on the host it is enabled on.
            if "header_regex" in variant.get("match", {}):
                observable = tests.get("log_positive") or tests.get("header_positive")
                check(f"{sig['id']}/{variant['name']} fixture coverage", bool(observable),
                      "header-targeting variant has neither log_positive nor header_positive fixtures")

            # Drift check between the store regex and the generated Apache rule.
            inline = variant.get("apache_inline")
            if inline and "uri_regex" in variant.get("match", {}):
                cond = re.search(r"RewriteCond\s+%\{REQUEST_URI\}\s+(.+)$", inline, re.M)
                if cond:
                    inline_rx = compile_regex(f"{variant['name']}.apache_inline", cond.group(1).strip())
                    same = (inline_rx is not None and
                            inline_rx.pattern == variant["match"]["uri_regex"])
                    check(f"{sig['id']}/{variant['name']} apache_inline drift", same,
                          f"RewriteCond regex {cond.group(1).strip()!r} != "
                          f"uri_regex {variant['match']['uri_regex']!r}")

    for sig in signatures:
        for signal in sig.get("corroborating_signals", []):
            signal.setdefault("id", sig["id"])
            signal.setdefault("name", signal.get("name", "signal"))
            print(f"  ~ corroborating: {signal['name']}")
            for raw in signal.get("test_positive", []):
                check_fixture("signal-positive", signal, raw)

    print(f"\nchecks run: {checks}   failures: {len(failures)}")
    for failure in failures:
        print(f"  FAIL {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
