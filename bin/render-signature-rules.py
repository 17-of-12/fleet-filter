#!/usr/bin/env python3
"""Render an Apache vhost include from the Path A signature store (Bundle L1, v3).

Purpose
-------
`controller/signatures/signatures.yaml` declares signatures, but nothing on a host executed
them (code-review finding PT-13). This renders the enforceable subset into real directives so
the request that *triggers* classification is the request the tarpit serves, instead of the
request that gets logged and acted on seconds later.

Why generation instead of hand-written rules
--------------------------------------------
Hand-written rules drift from the store, and a rule that silently stops matching is
indistinguishable from a signature that never fires. Generation makes the store the single
source of truth and forces every variant to be *classified* - enforceable, log-only, or
disabled - which is the "refuse, do not silently no-op" safety rule expressed in code.

Measured Apache 2.4.37 behaviour that shaped v3 (lab-web01, 2026-11-14)
------------------------------------------------------------------------
Three things were assumed and then measured on a scratch vhost whose upstream request was
captured with a raw socket listener, because "configtest passed" does not mean a directive
produced the intended header:

1. `RequestHeader set X "%{REMOTE_ADDR}e"` yields the literal value `(null)`.
   The `e` suffix means "look in the subprocess environment table", and REMOTE_ADDR is not
   populated there at fixup time on this build. The header has therefore been shipping
   `(null)` since PT-10 was implemented; the responder only reported the right client
   because it falls back to the `X-Forwarded-For` that mod_proxy adds itself. Fix: derive
   the value with `SetEnvIf Remote_Addr "^(.*)$" tarpit-client=$1` and read
   `%{tarpit-client}e`, which measures correctly (`X-Tarpit-Client: 198.51.100.72`).

2. A `RewriteRule` `E=var=value` flag is also invisible to mod_headers on this build -
   `%{tarpit-sig}e` came back `(null)` for a rule that had just proxied with
   `[P,L,E=tarpit-sig=testvalue]`. `SetEnvIf`/`SetEnvIfExpr` (post-read phase) are visible.
   So v2's per-rule `E=` approach could never name the matching variant, and v3 uses
   SetEnvIf exclusively.

3. In a `SetEnvIfExpr` expression, `X eq 'Y'` parses but is always truthy - `SetEnvIfExpr
   "'' eq 'x'"` set its variable. The real string-equality operator is `==`: with `==`,
   `%{REQUEST_METHOD} == 'CONNECT'` correctly stayed unset on a GET request while
   `%{REQUEST_METHOD} == 'GET'` set its variable. v2 emitted `eq`, so *every* variant
   matched *every* request and the last one in the file won. Verified set (all correct):
   `==` with single-quoted literals, `&&`, `||`, parentheses, `-n %{HTTP:Name}`, `!(...)`.
   Forms that fail to parse: `-str_eq ...`, `-eq`, `req_method`, and any double quote
   nested inside the quoted expression.

Every rule in the generated file is still validated with `httpd -t` before a reload, because
a parse error in an expression is only reported at config-parse time, not at request time.

v3 shape
--------
    SetEnvIf Remote_Addr "^(.*)$" tarpit-client=$1        # client identity (fixes PT-10)
    SetEnvIf / SetEnvIfExpr ... tarpit-sig=<ref>           # name the matching variant
    RequestHeader set X-Tarpit-Client "%{tarpit-client}e"
    RequestHeader set X-Tarpit-Signature "%{tarpit-sig}e" env=tarpit-sig
    RewriteCond %{ENV:tarpit-sig} !^$                      # route only named requests
    RewriteRule ^(.*)$ <backend>$1 [P,L]

Expressibility is decided explicitly, not by compiling something anyway:
  * `enabled: false`               -> skipped, reason carried from the store
  * tier 1 not in `tier`           -> skipped (log-only signature)
  * `requires: h2_aware_engine`    -> skipped (framing is invisible to mod_rewrite)
  * `posture:` set and unsatisfied -> skipped (the h2c preface is rejected at parse time
    when `Protocols` excludes h2c, so no rewrite rule ever runs for it)
  * not expressible in the verified syntax -> skipped, never emitted as a silent no-op

The store's `apache_inline:` snippets are not the input; `match:` is the contract, so
conditions are generated from it and `apache_inline` stays as prose.
"""

import argparse
import hashlib
import os
import re
import sys
import time

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML presence is checked by the caller
    sys.stderr.write("PyYAML is required to render signature rules\n")
    raise

# The variable that names the matching variant. One name keeps the attribution header and
# the routing condition to one line each; see `env_assignment` for collision behaviour.
SIG_ENV = "tarpit-sig"

# --- Bundle L3: the ReDoS gate (see redos_assessment) -------------------------------------
# Overridable at runtime with --allow-redos so an operator can ship a flagged pattern after
# reading the reason, instead of the gate becoming a reason to bypass the renderer.
ALLOW_REDOS = False
MAX_REGEX_LENGTH = 256
COMPILE_CEILING_SECONDS = 0.05
NESTED_QUANTIFIER_RE = re.compile(r"\([^()]*(?:[+*]|\{[0-9]+,?[0-9]*\})\)[+*?]")
ALT_UNDER_QUANTIFIER_RE = re.compile(r"\([^()]*\|[^()]*\)[+*]")
ADJACENT_WILDCARD_RE = re.compile(r"\.\*\.\*")

# The variable that carries the client address to the backend (PT-10). Set with SetEnvIf
# because a RewriteRule E= flag and %{REMOTE_ADDR}e both fail on this Apache line.
CLIENT_ENV = "tarpit-client"

# Match fields the declarative schema is allowed to use. A field outside this set means the
# variant is not expressible and the renderer must say so rather than emit a partial rule.
SUPPORTED_MATCH_FIELDS = (
    "uri_regex",
    "method",
    "protocol",
    "content_type_present",
    "content_length_in",
    "header",
    "header_regex",
)

# Apache's SERVER_PROTOCOL value for each protocol name in the store. h2 and h2c both
# surface as HTTP/2.0 once negotiated, so telling them apart needs an h2-aware engine - a
# real precision limit, stated rather than hidden.
SERVER_PROTOCOL_FOR = {
    "h2": "HTTP/2.0",
    "h2c": "HTTP/2.0",
    "http/1.1": "HTTP/1.1",
    "http/1.0": "HTTP/1.0",
}


def redos_assessment(regex):
    """Return `(risk, reason)` for a URI regex, implementing the Bundle L3 CI gate.

    Why this is checked at render time rather than at test time: a signature's regex is
    copied verbatim into every vhost that includes the generated file, and Apache evaluates
    it with PCRE on *every* request that reaches the fixup phase. One catastrophic-backtrack
    pattern therefore costs every client on the host, not just the client that triggered it -
    the same worker-exhaustion failure mode this project already guards against for the
    tarpit itself (docs/DETECTION-INPUTS.md, resource protection).

    The checks are structural rather than a simulation, because Python's `re` and Apache's
    PCRE backtrack differently and a Python-only match timing would not transfer. The shapes
    below are the ones that blow up on any backtracking engine:

      * a quantified group closed under another quantifier - `(a+)+`, `(a|ab)*`, `(x{2,})+`
      * two adjacent unbounded wildcards - `.*.*`, which multiplies the split points
      * a pattern so large its compiled program, not its semantics, is the cost

    A compile-time ceiling is measured as well. It is a weak signal on modern CPython, so it
    is a ceiling rather than the primary check; the structural rules do the real work.
    """
    if len(regex) > MAX_REGEX_LENGTH:
        return True, "pattern length %d exceeds %d" % (len(regex), MAX_REGEX_LENGTH)

    # (x+)+ / (x+)* / (x+){2,} - the classic exponential shape.
    if NESTED_QUANTIFIER_RE.search(regex):
        return True, "quantified group inside another quantifier (e.g. (a+)+)"
    # (a|ab)+ - alternation of overlapping literals under a quantifier.
    if ALT_UNDER_QUANTIFIER_RE.search(regex):
        return True, "alternation inside a quantified group (e.g. (a|ab)+)"
    # .*.* - two unbounded wildcards adjacent to each other.
    if ADJACENT_WILDCARD_RE.search(regex):
        return True, "adjacent unbounded wildcards (e.g. .*.*)"

    started = time.perf_counter()
    try:
        re.compile(regex)
    except re.error as exc:
        return True, "does not compile: %s" % exc
    elapsed = time.perf_counter() - started
    if elapsed > COMPILE_CEILING_SECONDS:
        return True, "compile took %.3fs, over the %.3fs ceiling" % (elapsed, COMPILE_CEILING_SECONDS)
    return False, ""


def as_list(value):
    """Normalise a store field that may be a scalar or a list into a list of strings.

    The schema wobbles between `method: PRI` and `method: [GET]` depending on when a variant
    was written; normalising here means every renderer path handles both instead of one of
    them silently producing `['P','R','I']`.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if str(v) != ""]
    return [str(value)] if str(value) != "" else []


def literal(text):
    """Return `text` as a single-quoted expression literal, or None if it cannot be one.

    Expressions on this build reject a double quote nested inside the quoted expression, so
    single quotes are the only usable quoting style; a value containing a single quote cannot
    be expressed and the caller treats the whole variant as unexpressible rather than
    emitting something that parses differently from what the store says.
    """
    if "'" in text or '"' in text:
        return None
    return "'" + text + "'"


def ref_name(signature, variant):
    """Return the `CVE/variant` reference that identifies this match in logs and claims."""
    return "%s/%s" % (signature.get("id", "?"), variant.get("name", "?"))


def expression_for(match):
    """Build a verified Apache 2.4 expression for a match block, or None if not expressible.

    Only constructs measured to behave correctly on httpd 2.4.37 are emitted: `==` with
    single-quoted literals, `&&`, `||`, parentheses, and `-n` for header-presence. `eq` is
    deliberately avoided - it parses but is always truthy (see the module docstring).
    """
    parts = []

    if "method" in match:
        methods = as_list(match["method"])
        if not methods:
            return None
        lits = [literal(m) for m in methods]
        if any(lit is None for lit in lits):
            return None
        comparisons = ["%{REQUEST_METHOD} == " + lit for lit in lits]
        parts.append(comparisons[0] if len(comparisons) == 1
                     else "(" + " || ".join(comparisons) + ")")

    if "protocol" in match:
        protocols = [str(p).lower() for p in as_list(match["protocol"])]
        values = []
        for protocol in protocols:
            value = SERVER_PROTOCOL_FOR.get(protocol)
            if value is None:
                return None
            if value not in values:
                values.append(value)
        if not values:
            return None
        comparisons = ["%{SERVER_PROTOCOL} == '" + v + "'" for v in values]
        parts.append(comparisons[0] if len(comparisons) == 1
                     else "(" + " || ".join(comparisons) + ")")

    if "content_type_present" in match:
        present = match["content_type_present"]
        if present is True:
            parts.append("-n %{HTTP:Content-Type}")
        elif present is False:
            parts.append("%{HTTP:Content-Type} == ''")
        else:
            return None

    if "content_length_in" in match:
        values = as_list(match["content_length_in"])
        if not values:
            return None
        # An absent header expands to the empty string in an expression even though the
        # access log records `-`; the store lists both spellings from measured lines, so
        # `-` and '' are the same case.
        comparisons = []
        for value in values:
            if value == "":
                comparisons.append("%{HTTP:Content-Length} == ''")
                continue
            lit = literal(value)
            if lit is None:
                return None
            comparisons.append("%{HTTP:Content-Length} == " + lit)
        if "" not in values and "-" in values:
            comparisons.append("%{HTTP:Content-Length} == ''")
        parts.append(comparisons[0] if len(comparisons) == 1
                     else "(" + " || ".join(comparisons) + ")")

    if "header" in match and "header_regex" in match:
        # A named header with a *regex* value needs PCRE, which an expression does not
        # provide; that combination is handled by SetEnvIf in `env_assignment`, not here.
        return None

    if "header_regex" in match and "header" not in match:
        # A header-name pattern (x-pad-000..077) cannot be addressed by expression at all:
        # %{HTTP:Name} names one header, it does not enumerate which ones are present.
        return None

    return " && ".join(parts) if parts else None


def env_assignment(signature, variant):
    """Return `(mechanism, line, detail)` for the statement that names this variant.

    Prefers `SetEnvIf Request_URI` when the whole match is a URI regex, because that form
    takes a real PCRE and needs no expression parser. Falls back to `SetEnvIfExpr` for
    method/protocol/header matches - the subset the expression language covers correctly.
    Returns mechanism `None` when neither can express the match without weakening it, which
    is how a variant becomes a reported gap instead of a rule that silently matches more.
    """
    match = variant.get("match") or {}
    ref = ref_name(signature, variant)
    if not match:
        return None, None, "no match block"
    unsupported = set(match) - set(SUPPORTED_MATCH_FIELDS)
    if unsupported:
        return None, None, "match fields Apache cannot read: %s" % ",".join(sorted(unsupported))

    if "uri_regex" in match and not (set(match) - {"uri_regex"}):
        regex = str(match["uri_regex"])
        try:
            re.compile(regex)
        except re.error as exc:
            return None, None, "invalid uri_regex %r: %s" % (regex, exc)
        if not ALLOW_REDOS:
            risk, why = redos_assessment(regex)
            if risk:
                return None, None, "ReDoS guard: %s (%r)" % (why, regex)
        return "setenvif", 'SetEnvIf Request_URI "%s" %s=%s' % (regex, SIG_ENV, ref), "uri_regex PCRE"

    if "uri_regex" in match:
        # uri_regex plus other fields: SetEnvIf can test the URI *or* the other field but
        # not both, and the expression form cannot test a URI regex. Half the match would
        # widen it, so the variant is reported rather than rendered partially.
        return None, None, "uri_regex combined with other fields needs both PCRE and an expression"

    expression = expression_for(match)
    if expression is None:
        return None, None, "match cannot be expressed with SetEnvIf/SetEnvIfExpr"
    return "setenvifexpr", 'SetEnvIfExpr "%s" %s=%s' % (expression, SIG_ENV, ref), "expression"


def classify_variant(signature, variant):
    """Decide whether one variant may be rendered, returning `(renderable, reason)`.

    The reason is emitted into the generated file so an operator reading
    `/etc/httpd/tarpit-signatures.conf` learns why a documented signature produced no rule -
    the difference between a reviewed decision and an unexplained gap.
    """
    if variant.get("enabled") is False:
        return False, "disabled in store: %s" % (variant.get("disabled_reason") or "no reason given").strip()

    tiers = as_list(variant.get("tier"))
    if tiers and not any(t == "1" for t in tiers):
        return False, "not a tier-1 signature (tier=%s); log-only" % ",".join(tiers)

    requires = variant.get("requires")
    if requires == "h2_aware_engine":
        return False, "requires an h2-aware engine; framing is invisible to mod_rewrite"
    if requires not in (None, "header_logging"):
        return False, "unsupported requirement: %s" % requires

    if variant.get("posture") == "protocols_exclude_h2c":
        return False, (
            "posture protocols_exclude_h2c: Apache rejects the h2c preface at parse time, "
            "so no rewrite rule runs for it (Tier 2 only, as the store states)"
        )

    mechanism, _line, detail = env_assignment(signature, variant)
    if mechanism is None:
        return False, "not expressible: %s" % detail

    return True, "rendered via %s (%s)" % (mechanism, detail)


def render(store, backend, include_marker):
    """Render the store into the text of an Apache include file.

    Returns `(text, rendered, skipped)`. `backend` is the tarpit URL the rules proxy to, so
    the same generated file can target the native responder today and the Stage 2 gateway
    later without changing a rule.
    """
    rendered = []
    skipped = []
    for signature in store.get("signatures", []):
        for variant in signature.get("variants", []):
            ok, reason = classify_variant(signature, variant)
            if ok:
                rendered.append((ref_name(signature, variant), signature, variant, reason))
            else:
                skipped.append((ref_name(signature, variant), reason))

    lines = [
        "# GENERATED FILE - DO NOT EDIT BY HAND",
        "# Source: controller/signatures/signatures.yaml",
        "# Renderer: bin/render-signature-rules.py",
        "# Marker: %s" % include_marker,
        "#",
        "# Tier 1 enforcement (DETECTION-INPUTS.md 2). Include this file *inside* a",
        "# <VirtualHost>, after the Tier 0 RewriteMap rules: the map rules end with [L], so",
        "# anything reaching these directives is by definition an unmapped client - the",
        "# population Tier 1 exists to catch. A conf.d copy is not enough: server-scope",
        "# mod_rewrite does not apply to requests served by a named vhost on httpd 2.4.37.",
        "#",
        "# This file is also the single place that tells the backend who the client is. The",
        "# per-vhost `RequestHeader set X-Tarpit-Client \"%{REMOTE_ADDR}e\"` it replaces",
        "# resolved to the literal `(null)` on this Apache line (see the renderer docstring),",
        "# so both attribution headers are generated here and vhosts must not add their own.",
        "#",
        "# Matching uses SetEnvIf/SetEnvIfExpr (post-read phase). RewriteRule E= flags and",
        "# the `eq` expression operator are both unreliable on httpd 2.4.37; the syntax here",
        "# is the subset verified against a live vhost on 2026-11-14.",
        "",
        "# %d renderable / %d skipped" % (len(rendered), len(skipped)),
        "",
        "# ---- 1. identity: who is asking (PT-10) ----",
        'SetEnvIf Remote_Addr "^(.*)$" %s=$1' % CLIENT_ENV,
        "",
        "# ---- 2. name the variant that matched: every renderable variant writes $%s ----" % SIG_ENV,
        "# Two variants matching one request is resolved by file order (last SetEnvIf wins),",
        "# which is visible here instead of being implicit in module merge order.",
    ]

    for ref, signature, variant, _reason in rendered:
        _mechanism, line, _detail = env_assignment(signature, variant)
        lines.append("# variant: %s  (verdict=%s response_profile=%s)" % (
            ref,
            variant.get("verdict_to_report", signature.get("verdict_to_report", "vulnerable")),
            variant.get("response_profile", signature.get("response_profile_default", "generic_slow")),
        ))
        lines.append("  %s" % line)

    lines.extend([
        "",
        "# ---- 3. tell the backend what it is answering ----",
        "# X-Tarpit-Client is always present; X-Tarpit-Signature only exists when a variant",
        "# matched, so a Tier 0 (map-only) request never receives a signature it did not",
        "# trigger and the responder can tell 'quarantined' from 'quarantined and why'.",
        'RequestHeader set X-Tarpit-Client "%%{%s}e"' % CLIENT_ENV,
        'RequestHeader set X-Tarpit-Signature "%%{%s}e" env=%s' % (SIG_ENV, SIG_ENV),
        "",
        "# ---- 4. route named requests to the tarpit ----",
        "RewriteCond " + "%{ENV:" + SIG_ENV + "} !^$",
        "RewriteRule ^(.*)$ %s$1 [P,L]" % backend,
        "",
    ])

    if skipped:
        lines.append("# ---- skipped variants (why this file has no rule for them) ----")
        for ref, reason in skipped:
            lines.append("#   %s -- %s" % (ref, reason))
        lines.append("")

    return "\n".join(lines) + "\n", rendered, skipped


def main(argv=None):
    """CLI: read the store, write the include, and print the render/skip decisions.

    Exits non-zero when nothing is renderable: an empty include is almost always a store or
    schema problem, and failing loudly is cheaper than deploying a file that enforces nothing.
    """
    parser = argparse.ArgumentParser(description="Render Apache Tier 1 rules from the signature store")
    parser.add_argument(
        "--store",
        default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "controller", "signatures", "signatures.yaml"),
        help="path to signatures.yaml",
    )
    parser.add_argument("--backend", default="http://127.0.0.1:8081", help="tarpit backend URL")
    parser.add_argument("--out", required=True, help="file to write the include to")
    parser.add_argument("--stdout", action="store_true", help="also print the rendered rules")
    parser.add_argument(
        "--allow-redos",
        action="store_true",
        help="render patterns the Bundle L3 ReDoS gate flags, and print the flags as warnings",
    )
    args = parser.parse_args(argv)

    global ALLOW_REDOS
    ALLOW_REDOS = args.allow_redos

    with open(args.store) as handle:
        store = yaml.safe_load(handle)

    text, rendered, skipped = render(store, args.backend, "tarpit-signatures")
    if not rendered:
        sys.stderr.write("no renderable signatures - refusing to write an empty include\n")
        return 1

    # When the gate is overridden, the flags must still be visible on the command output:
    # a silent override is how a known-bad pattern ends up in production.
    if args.allow_redos:
        for _ref, signature, variant, _reason in rendered:
            match = variant.get("match") or {}
            regex = match.get("uri_regex")
            if regex and "uri_regex" in match and set(match) == {"uri_regex"}:
                risk, why = redos_assessment(str(regex))
                if risk:
                    sys.stderr.write("warning: --allow-redos overriding the ReDoS gate for %s: %s\n" % (_ref, why))

    out = args.out
    tmp = out + ".tmp"
    with open(tmp, "w") as handle:
        handle.write(text)
    os.replace(tmp, out)

    digest = hashlib.sha256(text.encode()).hexdigest()[:12]
    print("wrote %s (%d rules, %d skipped, sha256:%s)" % (out, len(rendered), len(skipped), digest))
    if args.stdout:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
