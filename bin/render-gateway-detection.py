#!/usr/bin/env python3
"""Render the Stage 2 gateway's `[detection]` section from the Path A signature store.

Why this exists (code-review finding PTN-05)
--------------------------------------------
`gateway/policies/lab-web01.toml` carried two things by hand:

    [detection]
    prefixes = ["/h2probe-"]
    signatures = ["CVE-2026-119618:probe_path"]

`signatures` is only *checked* for shape by the gateway (`validate_signature_reference` in
`gateway/src/policy/mod.rs`); nothing proves the ids exist in the store, so a policy could name a
signature nobody wrote. `prefixes` is the list the gateway actually matches, and it was maintained
by hand - so the store could gain a variant, or change a pattern, and the deployed matcher would
keep quietly matching the old shape. That is the drift the ADR-0001 vocabulary rule exists to
prevent, and it is the same failure `bin/render-signature-rules.py` already fixed on the Apache
side (PT-13).

The answer to "can we not share a copy of the regex from a database?" is yes, and this is the
mechanism: the store is the one copy, and each consumer's matcher set is *generated* from it.
The gateway deliberately has no regex crate (ADR-0001 M2 pins the lockfile, and the Bundle S
benchmark measured 74 ns per URI with a literal matcher against 621 us with a regex set), so what
it consumes is the store's literal projection, not the regex itself.

What "expressible" means here
-----------------------------
A variant is enforceable by the gateway only if its URI pattern can be stated as literal prefixes:

  * `gateway_prefixes:` on the variant - the explicit declaration, validated against the store's
    own `tests.positive` fixtures (every declared prefix must actually prefix a fixture that the
    store already proves matches, and must contain no regex metacharacters);
  * otherwise, a plain anchored literal regex (`^/wp-json/batch/v1$`) - the literal is the prefix;
  * otherwise the variant is reported `unsupported` with a reason, and the policy does not claim
    it. A signature the gateway cannot match is listed as unenforced rather than emitted as a
    prefix that matches traffic the regex would have rejected - the project's "refuse, do not
    silently no-op" rule, applied to the gateway instead of Apache.

Usage
-----
    bin/render-gateway-detection.py [--store PATH] [--out PATH] [--stdout]

Exit status: 0 rendered; 1 the store produced nothing enforceable or a declaration was invalid.
"""

import argparse
import datetime
import hashlib
import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML presence is checked by the caller
    sys.stderr.write("PyYAML is required to render gateway detection\n")
    raise

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_STORE = os.path.join(REPO_ROOT, "controller", "signatures", "signatures.yaml")

# Characters that make a string a pattern rather than a literal. A declared prefix containing any
# of them is a declaration of a regex where a literal was asked for, which is how a hand-written
# prefix ends up matching things the store's regex does not.
METACHARACTERS = set("()[]{}?*+|^$\\.")


def literal_prefix(uri_regex):
    """Return the leading literal of an anchored `uri_regex`, or None when it has none.

    `^/h2probe-[0-9]{1,8}$` yields `/h2probe-`; `^(?:/|/index\\.php)...` yields None because the
    pattern opens with an alternation, so no single literal describes what it matches. Escapes
    (`\\?`, `\\.`) are unfolded to the character they match, so a pattern that is literal apart
    from its escapes still yields a usable prefix.
    """
    if not uri_regex.startswith("^"):
        return None
    body = uri_regex[1:]
    out = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "$" and index == len(body) - 1:
            break
        if char == "\\":
            nxt = body[index + 1] if index + 1 < len(body) else ""
            # \d, \w, \s and friends are classes, not literals; \x2a-style escapes are literals.
            if nxt in ("d", "w", "s", "D", "W", "S", "b", "B", "x", "0", "n", "r", "t"):
                break
            out.append(nxt)
            index += 2
            continue
        if char in METACHARACTERS:
            break
        out.append(char)
        index += 1
    prefix = "".join(out)
    # `/` is not a projection, it is a wildcard: a policy carrying it flags every request on the
    # host. `^/{2,}wp-json/batch/v1$` walks to `/` and stops at the quantifier, so the caller has
    # to declare the real literals instead of letting the derivation silently widen to everything.
    return prefix if prefix not in ("", "/") else None


def variant_reference(signature_id, variant):
    """Return the `ID:variant` reference the gateway policy uses for this variant."""
    return "%s:%s" % (signature_id, variant.get("name", "unnamed"))


def classify_variant(signature_id, variant):
    """Decide what the gateway can do with one variant.

    Returns `(reference, status, prefixes, reason)` where status is `enforced`, `log-only`
    (the store says the variant is not inline-enforceable), `disabled`, or `unsupported`.
    """
    reference = variant_reference(signature_id, variant)
    if not variant.get("enabled", True):
        return reference, "disabled", [], variant.get("disabled_reason", "enabled: false")

    tiers = [int(tier) for tier in variant.get("tier", [])]
    if 1 not in tiers:
        return reference, "log-only", [], "tier %s does not include tier 1 (inline enforcement)" % tiers

    match = variant.get("match", {}) or {}
    if set(match) == {"body_marker"}:
        # Enforced, but by the body-marker list rather than by a URI prefix. Reporting it as
        # "unsupported (no uri_regex)" was true for the prefix projection and false for the policy,
        # which is the kind of half-truth that makes an operator distrust the whole report.
        return reference, "body", [], "enforced by the body_markers list"
    uri_regex = match.get("uri_regex")
    declared = variant.get("gateway_prefixes")

    if declared is None and uri_regex is None:
        # Method/protocol/header-only variants (e.g. the h2c preface) have no URI to prefix-match;
        # the gateway's detection surface is URI prefixes, so it cannot enforce them inline.
        return reference, "unsupported", [], "variant declares no uri_regex (gateway matches URI prefixes only)"

    prefixes = []
    if declared is not None:
        if not isinstance(declared, list) or not declared:
            return reference, "unsupported", [], "gateway_prefixes must be a non-empty list"
        for prefix in declared:
            if not isinstance(prefix, str) or not prefix:
                return reference, "unsupported", [], "gateway_prefixes contains an empty or non-string entry"
            # Anchors are the one regex syntax a URI can never contain, so they are what catches
            # someone pasting a pattern where a literal was asked for. `?`, `(` and `*` are legal
            # URI characters (`/?rest_route=/batch/v1`), so they are not rejected on their own.
            if prefix.startswith("^") or prefix.endswith("$"):
                return reference, "unsupported", [], (
                    "gateway_prefixes entry %r looks like a regex, not a literal" % prefix
                )
            prefixes.append(prefix)
        # A declared prefix has to describe a request the store proves matches. Without this check
        # the declaration is a claim, and the claim is what drifts.
        fixtures = list((variant.get("tests", {}) or {}).get("positive", [])) + \
            [line.split(" ")[1] for line in (variant.get("tests", {}) or {}).get("log_positive", [])
             if line.count(" ") > 1]
        if not fixtures:
            return reference, "unsupported", [], "gateway_prefixes declared but the variant has no positive fixtures"
        for prefix in prefixes:
            if not any(fixture.startswith(prefix) for fixture in fixtures):
                return reference, "unsupported", [], (
                    "gateway_prefixes entry %r matches no positive fixture of %s" % (prefix, reference)
                )
        return reference, "enforced", prefixes, "declared via gateway_prefixes"

    derived = literal_prefix(uri_regex)
    if derived is None:
        return reference, "unsupported", [], (
            "uri_regex %r has no literal prefix; declare gateway_prefixes to enforce it" % uri_regex
        )
    return reference, "enforced", [derived], "derived from uri_regex"


def shape_line(signature_id, variant):
    """Project a variant's `match` into one gateway shape line, or None when it is not expressible.

    The gateway can test request properties it already parses - protocol version, method, whether
    Content-Type is present, the state of Content-Length, a header-name prefix and the header count.
    It cannot test a URI regex (that is the prefix projection), a header value regex, or anything
    about the body. A variant is projected only when every predicate it declares is in the former
    set, because a shape that silently drops a predicate is a rule that fires on more than the store
    says it does.
    """
    match = variant.get("match") or {}
    if not variant.get("enabled", True):
        return None
    if variant.get("posture"):
        # A posture-dependent variant (`posture: protocols_exclude_h2c`) is enforceable only on a
        # host that has taken that posture, and a gateway policy does not express posture. Measured
        # 2026-11-24: a cleartext `PRI * HTTP/2.0` preface sent to the TLS listener fails the
        # handshake, so hyper never sees method PRI and the shape could never fire - a rule that
        # matches nothing, which is the failure this project refuses.
        return None
    if 1 not in [int(tier) for tier in variant.get("tier", [])]:
        return None
    expressible = {"protocol", "method", "content_type_present", "content_length_in",
                   "header_name_regex", "header_count_at_least"}
    if not match or not set(match).issubset(expressible):
        return None
    if not (match.keys() & {"protocol", "method", "content_type_present",
                            "content_length_in", "header_name_regex"}):
        return None

    tokens = ["%s:%s" % (signature_id, variant["name"])]
    if match.get("protocol"):
        tokens.append("protocol=%s" % ",".join(match["protocol"]))
    if match.get("method"):
        tokens.append("method=%s" % ",".join(match["method"]))
    if "content_type_present" in match:
        tokens.append("ct=%s" % ("present" if match["content_type_present"] else "absent"))
    if match.get("content_length_in"):
        states = []
        for value in match["content_length_in"]:
            if value == "-":
                states.append("absent")
            elif value == "0":
                states.append("zero")
            else:
                states.append("present")
        tokens.append("cl=%s" % ",".join(sorted(set(states))))
    if match.get("header_name_regex"):
        # Only a literal prefix is expressible; `^x-pad-[0-7][0-9]$` reduces to `x-pad-`, which is
        # broader than the regex and is recorded as such in the rendered comment.
        prefix = match["header_name_regex"].lstrip("^")
        cut = min([prefix.find(char) for char in "[$*+?(" if char in prefix] or [len(prefix)])
        prefix = prefix[:cut]
        if not prefix:
            return None
        tokens.append("header_prefix=%s" % prefix)
    if match.get("header_count_at_least"):
        tokens.append("min_headers=%d" % int(match["header_count_at_least"]))
    return " ".join(tokens)


def body_marker(signature_id, variant):
    """Project a variant's `match` into a request-body marker, or None when it has no marker.

    A marker is a literal the gateway searches for in the request body, which it already
    buffers up to `max_body_bytes`. Only the engine class needs this surface: PHP2Shell's
    trigger is a multipart field the PHP engine parses before any application code runs, so
    no URI or header predicate can see it. A variant projects a marker only when it is
    enabled, runs at tier 1, and its match block is *exactly* `body_marker` - a match that
    mixes the marker with other predicates would claim a check the gateway cannot express.
    """
    if not variant.get("enabled", True):
        return None
    if 1 not in [int(tier) for tier in variant.get("tier", [])]:
        return None
    match = variant.get("match") or {}
    if set(match) != {"body_marker"}:
        return None
    marker = match["body_marker"]
    if not isinstance(marker, str) or not marker:
        return None
    return marker


def render(store_text, store_path, selected=None, excluded=()):
    """Render the `[detection]` section plus a provenance comment from the store text.

    `selected` (a set of signature ids) and `excluded` (ids) let one store render more than one rule
    set, which is what A/B testing needs: the same patterns, a different enforcement decision, and a
    policy file that records which decision produced it. Filtering here rather than in the store means
    an A/B run never edits the source of truth, so two variants of the experiment can be compared
    with `git diff` still empty.
    """
    store = yaml.safe_load(store_text)
    rows = []
    for signature in store.get("signatures", []):
        if selected is not None and signature["id"] not in selected:
            continue
        if signature["id"] in excluded:
            continue
        for variant in signature.get("variants", []) or []:
            rows.append(classify_variant(signature["id"], variant))

    enforced = [(ref, prefixes) for ref, status, prefixes, _ in rows if status == "enforced"]
    # Structured shapes are a second projection of the same store: the protocol-class variants whose
    # predicates are request properties, not URI patterns. Body markers are a third: the
    # engine-class variants whose trigger is a literal in the request body itself.
    shape_lines = []
    body_markers = []
    for signature in store.get("signatures", []):
        if selected is not None and signature["id"] not in selected:
            continue
        if signature["id"] in excluded:
            continue
        for variant in signature.get("variants", []) or []:
            line = shape_line(signature["id"], variant)
            if line:
                shape_lines.append(line)
            marker = body_marker(signature["id"], variant)
            if marker:
                body_markers.append(marker)
    digest = hashlib.sha256(store_text.encode("utf-8")).hexdigest()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = [
        "# Generated by bin/render-gateway-detection.py - do not edit the [detection] table by hand.",
        "#   store: %s" % os.path.relpath(store_path, REPO_ROOT),
        "#   store_sha256: %s" % digest,
        "#   generated_at: %s" % stamp,
        "#   rule set: %s" % ("all" if selected is None and not excluded
                             else "only=%s exclude=%s" % (sorted(selected) if selected else "-",
                                                          sorted(excluded) or "-")),
        "#   variants: %d enforced, %d by body marker, %d unsupported, %d log-only, %d disabled"
        % (len(enforced),
           sum(1 for r in rows if r[1] == "body"),
           sum(1 for r in rows if r[1] == "unsupported"),
           sum(1 for r in rows if r[1] == "log-only"),
           sum(1 for r in rows if r[1] == "disabled")),
        "#",
        "# `prefixes` is the literal projection the gateway matches (it pins no regex crate, so it",
        "# cannot match a pattern - only the literals the store declares). `signatures` lists every",
        "# variant the store contains, in `ID:variant` form, so the policy states what the store",
        "# knows even where the gateway cannot enforce it.",
        "[detection]",
    ]

    if body_markers:
        rendered_markers = ",\n".join('  "%s"' % marker for marker in sorted(set(body_markers)))
        lines.append("#")
        lines.append("# `body_markers` are literal markers searched in the request body, which the")
        lines.append("# gateway already buffers up to max_body_bytes. They exist for the engine")
        lines.append("# class (PHP2Shell) where the trigger is a multipart body field parsed")
        lines.append("# before application code runs, so no URI or header predicate can see it.")
        lines.append("body_markers = [\n%s,\n]" % rendered_markers)
    else:
        lines.append("body_markers = []")

    if shape_lines:
        rendered_shapes = ",\n".join('  "%s"' % line for line in sorted(shape_lines))
        lines.append("#")
        lines.append("# `shapes` are predicates over request properties the gateway already parses")
        lines.append("# (protocol, method, Content-Type presence, Content-Length state, header-name")
        lines.append("# prefix, header count). They exist because the protocol-class variants cannot be")
        lines.append("# expressed as a URI prefix; the body is never read.")
        lines.append("shapes = [\n%s,\n]" % rendered_shapes)
    else:
        lines.append("shapes = []")

    prefix_list = sorted({prefix for _, prefixes in enforced for prefix in prefixes})
    if prefix_list:
        rendered = ",\n".join('  "%s"' % prefix for prefix in prefix_list)
        lines.append("prefixes = [\n%s,\n]" % rendered)
    else:
        lines.append("prefixes = []")

    references = sorted(variant_reference(sig["id"], v)
                        for sig in store.get("signatures", [])
                        for v in (sig.get("variants", []) or []))
    if references:
        rendered = ",\n".join('  "%s"' % ref for ref in references)
        lines.append("signatures = [\n%s,\n]" % rendered)
    else:
        lines.append("signatures = []")

    for reference, status, _, reason in rows:
        if status in ("enforced", "body"):
            # `body` is enforced, just through `body_markers` rather than through a URI prefix.
            # Listing it as "not enforced" made the report contradict the reason printed next to it.
            continue
        lines.append("# not enforced by the gateway: %s (%s: %s)"
                     % (reference, status, " ".join(str(reason).split())))
    return "\n".join(lines) + "\n", enforced, rows


def main(argv=None):
    """Parse arguments, render the section, and write or print it."""
    parser = argparse.ArgumentParser(description="Render the gateway [detection] section from the signature store")
    parser.add_argument("--store", default=DEFAULT_STORE, help="path to signatures.yaml")
    parser.add_argument("--out", help="file to write the rendered section to")
    parser.add_argument("--stdout", action="store_true", help="also print the rendered section")
    parser.add_argument("--only", action="append", default=[], metavar="SIG_ID",
                        help="render only these signature ids (repeatable); the same store, a smaller rule set")
    parser.add_argument("--exclude", action="append", default=[], metavar="SIG_ID",
                        help="render the store without these signature ids (repeatable)")
    args = parser.parse_args(argv)

    if not os.path.exists(args.store):
        sys.stderr.write("missing signature store: %s\n" % args.store)
        return 1
    with open(args.store) as handle:
        text = handle.read()

    unknown = sorted(set(args.only) - {sig["id"] for sig in yaml.safe_load(text).get("signatures", [])})
    if unknown:
        # A typo in an A/B variant would otherwise render a rule set that never says what was asked
        # for, and the run would look like "the signature changed nothing".
        sys.stderr.write("unknown signature id(s) in --only: %s\n" % ", ".join(unknown))
        return 2
    rendered, enforced, rows = render(text, args.store,
                                      selected=set(args.only) or None,
                                      excluded=set(args.exclude))
    if not rows:
        sys.stderr.write("store contains no signatures; refusing to write an empty detection section\n")
        return 1
    if not enforced:
        sys.stderr.write("no variant in the store is enforceable by the gateway; refusing to write\n%s" % rendered)
        return 1

    if args.out:
        directory = os.path.dirname(os.path.abspath(args.out))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(args.out, "w") as handle:
            handle.write(rendered)
    if args.stdout or not args.out:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
