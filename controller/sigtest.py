#!/usr/bin/env python3
"""E10 - replay the signature store against historical access logs before any rule is deployed.

The question this answers is not "does the regex compile" (the renderer already refuses bad patterns)
but "what would have happened if this signature set had been active last week". A signature that
matches nothing is dead weight; a signature that matches the monitoring system's own traffic is an
outage waiting to happen, because quarantining PRTG or a load balancer tarpits the thing watching the
service. Both are invisible to a unit test and both are visible in a week of access logs.

Three things are reported per variant, because each catches a different failure:
  * match count and example requests  - is the signature firing at all, and on what
  * distinct source addresses         - who would be quarantined (the actual blast radius)
  * evaluability                      - a variant that needs request headers cannot be judged from a
    log format that does not record them; saying so is the difference between a reviewed gap and a
    silent one, which is the same rule the renderer applies when it refuses header-targeting
    signatures on a `combined`-only vhost.

Python 3.9-compatible (operating rule 15).
"""

from __future__ import print_function

import argparse
import datetime
import json
import os
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the interpreter, not the code
    sys.stderr.write("error: PyYAML is required (see operating rule 15; use the project .venv)\n")
    raise SystemExit(1)

# One line of any Apache format Apache can be talked into emitting. The core is identical in common,
# combined and combinedio; the trailing key=value pairs are the project's own extensions (ct=/cl=/
# ho= from `tarpitext`, reqid=/xff= from `gatewaybackend`), captured generically so a new extension
# does not need a new parser.
LINE_RE = re.compile(
    r'^(?P<client>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>(?:[^"\\]|\\.)*)"\s+"(?P<agent>(?:[^"\\]|\\.)*)")?'
    r'(?P<extras>.*)$'
)
REQUEST_RE = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"\s]+))?$')
EXTRA_RE = re.compile(r'(?P<key>[A-Za-z][A-Za-z0-9_-]*)=(?P<value>\S+)')

# Match fields the store may use, and the log evidence each one needs. Mirrors
# bin/render-signature-rules.py's SUPPORTED_MATCH_FIELDS; a variant whose requirement cannot be
# satisfied by the log being read is reported as unevaluable rather than counted as a non-match.
HEADER_FIELD_FOR = {"content_type_present": "ct", "content_length_in": "cl"}


def as_strings(value):
    """Normalise a store value that may be a scalar or a list into a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def parse_line(line):
    """Return a dict describing one access-log line, or None if the line is not a request record."""
    line = line.rstrip("\n").rstrip("\r")
    if not line.strip() or line.startswith("#"):
        return None
    match = LINE_RE.match(line)
    if not match:
        return None
    fields = match.groupdict()
    request = REQUEST_RE.match(fields["request"] or "")
    fields["method"] = request.group("method") if request else None
    fields["path"] = request.group("path") if request else fields["request"]
    fields["protocol"] = (request.group("proto") if request else None) or "-"
    extras = {}
    for extra in EXTRA_RE.finditer(fields.get("extras") or ""):
        extras[extra.group("key").lower()] = extra.group("value")
    fields["extras"] = extras
    fields["formats"] = "combined_plus_extras" if extras else ("combined" if fields.get("agent") else "common")
    return fields


def parse_time(value):
    """Convert Apache's `14/Nov/2026:20:00:59 -0500` to a datetime, or None if it will not parse."""
    try:
        return datetime.datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    except (ValueError, TypeError):
        return None


def variant_requirements(match):
    """Return (needs_path, needs_headers) for one variant's `match` block.

    Header evidence is the part a log format can lack, so it is separated out: a variant matching on
    Content-Type or Content-Length can only be judged from a log that records them.
    """
    needs_path = "uri_regex" in match
    needed_headers = set()
    if "content_type_present" in match:
        needed_headers.add("ct")
    if "content_length_in" in match:
        needed_headers.add("cl")
    if "header" in match:
        needed_headers.add(str(match.get("header")).lower())
    if "header_regex" in match:
        needed_headers.add(str(match.get("header_regex") or [""])[0].lower())
    return needs_path, needed_headers


def evaluate(match, entry):
    """Return True/False/None - None means the log does not carry the evidence to decide.

    An empty or unrecognised `match` block is None, not True. The first version returned True for
    `framing_only_shapes`, a variant the store disables and gives no `match` at all (it names
    `shapes:` instead), so every request in the log "matched" it - the classic difference between a
    matcher and a matcher that matches everything.
    """
    if not any(key in match for key in (
            "uri_regex", "method", "protocol", "content_type_present",
            "content_length_in", "header", "header_regex")):
        return None
    needs_path, needed_headers = variant_requirements(match)
    available = entry["extras"]
    for header in needed_headers:
        if header not in available and header not in ("ct", "cl"):
            return None  # a named header the log format does not record
        if header in ("ct", "cl") and "ct" not in available and "cl" not in available:
            return None
    if needs_path:
        try:
            if not re.search(match["uri_regex"], entry["path"] or ""):
                return False
        except re.error:
            return None
    if "method" in match and entry["method"] not in as_strings(match["method"]):
        return False
    if "protocol" in match:
        from_store = {"h2": "HTTP/2.0", "h2c": "HTTP/2.0", "http/1.1": "HTTP/1.1", "http/1.0": "HTTP/1.0"}
        wanted = set(from_store.get(p.lower(), p) for p in as_strings(match["protocol"]))
        if entry["protocol"] not in wanted:
            return False
    if "content_type_present" in match:
        present = available.get("ct", "-") not in ("-", "")
        if bool(match["content_type_present"]) != present:
            return False
    if "content_length_in" in match:
        value = available.get("cl", "-")
        if value not in as_strings(match["content_length_in"]):
            return False
    for key in ("header", "header_regex"):
        if key not in match:
            continue
        for name in as_strings(match[key]):
            if available.get(name.lower(), "-") == "-":
                return None  # the log does not record this header
    return True


def analyse(paths, store_path, allowlist_path=None, max_examples=3):
    """Replay the store against each log file and return the report structure E10 asks for."""
    with open(store_path) as handle:
        store = yaml.safe_load(handle) or {}
    signatures = store.get("signatures") or []

    allowlist = set()
    if allowlist_path and os.path.isfile(allowlist_path):
        with open(allowlist_path) as handle:
            for line in handle:
                entry = line.split("#", 1)[0].strip()
                if entry:
                    allowlist.add(entry.split()[0])

    files = []
    variants_total = 0
    for path in paths:
        per_variant = {}
        disabled = {}
        total_lines = parsed = rejected = 0
        first_seen = last_seen = None
        with open(path, "r", errors="replace") as handle:
            for line in handle:
                total_lines += 1
                entry = parse_line(line)
                if entry is None:
                    rejected += 1
                    continue
                parsed += 1
                stamp = parse_time(entry["time"])
                if stamp is not None:
                    first_seen = stamp if first_seen is None or stamp < first_seen else first_seen
                    last_seen = stamp if last_seen is None or stamp > last_seen else last_seen
                for signature in signatures:
                    for variant in signature.get("variants") or []:
                        sig_id = "%s/%s" % (signature.get("id"), variant.get("name"))
                        if variant.get("enabled") is False:
                            # A disabled variant is reported, never evaluated: counting it as
                            # zero matches would hide the reason it is zero.
                            disabled[sig_id] = (variant.get("disabled_reason") or "no reason given").strip()[:120]
                            continue
                        slot = per_variant.setdefault(sig_id, {
                            "matches": 0, "ips": {}, "examples": [], "verdict": variant.get("response_profile"),
                        })
                        try:
                            outcome = evaluate(variant.get("match") or {}, entry)
                        except Exception as exc:  # a bad pattern must not abort the whole replay
                            slot["error"] = str(exc)
                            continue
                        if outcome is None:
                            slot["unevaluable"] = slot.get("unevaluable", 0) + 1
                            continue
                        if not outcome:
                            continue
                        slot["matches"] += 1
                        slot["ips"][entry["client"]] = slot["ips"].get(entry["client"], 0) + 1
                        if len(slot["examples"]) < max_examples:
                            slot["examples"].append("%s %s %s -> %s" % (
                                entry["client"], entry["method"], entry["path"], entry["status"]))
        variants_total += len(per_variant)
        files.append({
            "file": path, "lines": total_lines, "parsed": parsed, "unparsed": rejected,
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "variants": per_variant,
            "disabled_variants": disabled,
        })

    # The blast radius: every address any signature would have claimed, minus the allowlist.
    claimed = {}
    for file_report in files:
        for sig_id, slot in file_report["variants"].items():
            for ip, count in slot["ips"].items():
                claimed[ip] = claimed.get(ip, 0) + count
    quarantined = sorted(([ip, c] for ip, c in claimed.items() if ip not in allowlist), key=lambda x: -x[1])
    suppressed = sorted(([ip, c] for ip, c in claimed.items() if ip in allowlist), key=lambda x: -x[1])

    return {
        "store": store_path,
        "signatures": len(signatures),
        "variants": variants_total,
        "allowlist_size": len(allowlist),
        "files": files,
        "would_quarantine": quarantined,
        "allowlist_suppressed": suppressed,
    }


def render_text(report, max_ips=10):
    """Human-readable rendering of the analysis: per-file, then the blast radius."""
    lines = ["signature store: %s (%d signatures, %d variants)" % (
        report["store"], report["signatures"], report["variants"])]
    for file_report in report["files"]:
        lines.append("")
        lines.append("file: %s" % file_report["file"])
        lines.append("  lines=%d parsed=%d unparsed=%d window=%s..%s" % (
            file_report["lines"], file_report["parsed"], file_report["unparsed"],
            file_report["first_seen"], file_report["last_seen"]))
        matched = [(k, v) for k, v in sorted(file_report["variants"].items()) if v["matches"]]
        silent = [k for k, v in sorted(file_report["variants"].items()) if not v["matches"]]
        for sig_id, slot in matched:
            lines.append("  MATCH %-34s %5d  ips=%d  %s" % (
                sig_id, slot["matches"], len(slot["ips"]),
                "; ".join(slot["examples"][:2]) or "-"))
            if slot.get("unevaluable"):
                lines.append("        (%d requests could not be judged: missing header evidence)"
                             % slot["unevaluable"])
            if slot.get("error"):
                lines.append("        error: %s" % slot["error"])
        for sig_id in silent[:20]:
            lines.append("  none %-34s     0" % sig_id)
        if len(silent) > 20:
            lines.append("  ... %d more variants with no match" % (len(silent) - 20))
        for sig_id, reason in sorted(file_report.get("disabled_variants", {}).items()):
            lines.append("  disabled %-30s %s" % (sig_id, reason))
    lines.append("")
    lines.append("would quarantine %d addresses (allowlist suppressed %d):" % (
        len(report["would_quarantine"]), len(report["allowlist_suppressed"])))
    for ip, count in report["would_quarantine"][:max_ips]:
        lines.append("  %-18s %d request(s)" % (ip, count))
    if len(report["would_quarantine"]) > max_ips:
        lines.append("  ... %d more" % (len(report["would_quarantine"]) - max_ips))
    for ip, count in report["allowlist_suppressed"][:max_ips]:
        lines.append("  %-18s %d request(s) [allowlisted - not quarantined]" % (ip, count))
    return "\n".join(lines)


def main(argv=None):
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Replay the signature store against access logs (E10)")
    parser.add_argument("--log", action="append", required=True, help="access log to replay (repeatable)")
    parser.add_argument("--store", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                                         "controller", "signatures", "signatures.yaml"),
                        help="path to signatures.yaml")
    parser.add_argument("--allowlist", default="", help="controller allowlist to subtract from the verdict")
    parser.add_argument("--max-examples", type=int, default=3, help="example requests kept per variant")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args(argv)

    missing = [p for p in args.log if not os.path.isfile(p)]
    if missing:
        sys.stderr.write("error: no such log file(s): %s\n" % ", ".join(missing))
        return 1
    report = analyse(args.log, args.store, args.allowlist or None, args.max_examples)
    if all(f["parsed"] == 0 for f in report["files"]):
        sys.stderr.write("error: no parseable request lines in the given logs\n")
        return 1
    if args.json:
        print(json.dumps(report, indent=1, sort_keys=True))
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
