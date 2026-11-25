#!/usr/bin/env python3
"""Unit tests for bin/render-signature-rules.py (Bundle L1).

Purpose
-------
The renderer's output is deployed into a live Apache vhost, and the failure modes that
mattered were invisible to `httpd -t`: a `RewriteRule E=` flag that mod_headers cannot read,
and an `eq` expression operator that parses but is always true. Both were caught by
measurement on lab-web01, not by a test, so this suite encodes the *verified* syntax as
assertions. It exists to make the next renderer change fail here instead of on a host.

Checks are structural rather than a golden blob: a golden file would fail on every cosmetic
comment edit, while these assertions fail only when a rule stops being expressible the way
httpd 2.4.37 requires.
"""

import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RENDERER = os.path.join(ROOT, "bin", "render-signature-rules.py")
STORE = os.path.join(ROOT, "controller", "signatures", "signatures.yaml")

# The renderer needs PyYAML, which is present on this host's python3.9 but not python3.12,
# so the label is taken from the interpreter actually running the suite rather than a list.
RUNTIME = os.path.basename(sys.executable) or "python"

failures = []
checks = 0


def check(name, condition, detail=""):
    """Record one assertion and its outcome.

    Accumulates rather than aborts so a single run reports every broken rule, which is what
    makes the harness useful during a multi-file edit.
    """
    global checks
    checks += 1
    if not condition:
        failures.append("%s %s" % (name, detail))


def render_text(store_text, workdir, backend="http://127.0.0.1:8081"):
    """Render `store_text` with the renderer and return the generated file's text.

    Writes the store into `workdir` so a test can exercise a modified store without touching
    the real one, and returns None when the renderer exits non-zero (its "refuse to write an
    empty include" path).
    """
    store_path = os.path.join(workdir, "signatures.yaml")
    out_path = os.path.join(workdir, "tarpit-signatures.conf")
    with open(store_path, "w") as handle:
        handle.write(store_text)
    proc = subprocess.run(
        [sys.executable, RENDERER, "--store", store_path, "--out", out_path, "--backend", backend],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return None
    with open(out_path) as handle:
        return handle.read()


def balanced(text):
    """True when double quotes, single quotes and parentheses are balanced in `text`."""
    return (
        text.count('"') % 2 == 0
        and text.count("'") % 2 == 0
        and text.count("(") == text.count(")")
    )


def test_real_store():
    """Assert the shipped store renders into Apache directives that obey the verified syntax."""
    with open(STORE) as handle:
        store_text = handle.read()

    with tempfile.TemporaryDirectory() as workdir:
        text = render_text(store_text, workdir)
        check("[%s] renderer exits 0 for the shipped store" % RUNTIME, text is not None)
        if text is None:
            return

        check("[%s] header block present" % RUNTIME, "GENERATED FILE - DO NOT EDIT BY HAND" in text)
        check("[%s] renderer is named" % RUNTIME, "bin/render-signature-rules.py" in text)

        # PT-10: %{REMOTE_ADDR}e resolves to the literal "(null)" on httpd 2.4.37, so the
        # client address must come from SetEnvIf instead.
        check(
            "[%s] client identity comes from SetEnvIf" % RUNTIME,
            'SetEnvIf Remote_Addr "^(.*)$" tarpit-client=$1' in text,
        )
        check(
            "[%s] X-Tarpit-Client reads the SetEnvIf variable" % RUNTIME,
            'RequestHeader set X-Tarpit-Client "%{tarpit-client}e"' in text,
        )
        directives = [ln.strip() for ln in text.splitlines() if not ln.strip().startswith("#")]
        check(
            "[%s] no directive uses the %%{REMOTE_ADDR}e form" % RUNTIME,
            not any("%{REMOTE_ADDR}e" in ln for ln in directives),
            "this form yields the literal (null) on 2.4.37",
        )

        # RewriteRule E= flags are invisible to mod_headers on 2.4.37; only the routing rule
        # and the SetEnvIf statements may carry state.
        rules = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("RewriteRule ")]
        for rule in rules:
            check("[%s] RewriteRule has no E= flag: %s" % (RUNTIME, rule), "E=" not in rule)
        check(
            "[%s] exactly one routing RewriteRule" % RUNTIME,
            len([r for r in rules if r.startswith("RewriteRule ^(.*)$")]) == 1,
            "found %d" % len([r for r in rules if r.startswith("RewriteRule ^(.*)$")]),
        )
        conds = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("RewriteCond ")]
        check(
            "[%s] routing is gated on the signature env var" % RUNTIME,
            "RewriteCond %{ENV:tarpit-sig} !^$" in conds,
        )

        # Expressions must use `==`; `eq` parses but is always truthy on 2.4.37, which made
        # every variant match every request in renderer v2.
        exprs = re.findall(r'SetEnvIfExpr "(.*)"', text)
        for expr in exprs:
            check("[%s] expression uses == not eq: %s" % (RUNTIME, expr), " eq " not in expr)
            check("[%s] expression balanced: %s" % (RUNTIME, expr), balanced(expr))
        for line in text.splitlines():
            if line.strip().startswith("SetEnvIf "):
                check("[%s] SetEnvIf line balanced: %s" % (RUNTIME, line.strip()), balanced(line.strip()))

        # Every renderable variant must appear exactly once as an env assignment.
        refs = re.findall(r"tarpit-sig=(CVE-[0-9-]+/[a-z0-9_]+)", text)
        check("[%s] every assignment names a real variant" % RUNTIME, len(refs) >= 1, "found %d" % len(refs))
        check(
            "[%s] no duplicate variant assignment" % RUNTIME,
            len(refs) == len(set(refs)),
            "duplicates: %s" % [r for r in set(refs) if refs.count(r) > 1],
        )
        check(
            "[%s] skipped variants are documented" % RUNTIME,
            "skipped variants" in text,
        )

        # Idempotency: rendering twice must produce byte-identical output, otherwise the
        # generated file drifts on every deploy and cannot be diffed meaningfully.
        again = render_text(store_text, workdir)
        check("[%s] rendering is deterministic" % RUNTIME, again == text)


def test_empty_store():
    """Assert the renderer refuses to write an include when nothing is renderable.

    An empty include is the silent-no-op failure the safety rules forbid, so the CLI must exit
    non-zero rather than write a file that enforces nothing.
    """
    with tempfile.TemporaryDirectory() as workdir:
        store_path = os.path.join(workdir, "signatures.yaml")
        out_path = os.path.join(workdir, "tarpit-signatures.conf")
        with open(store_path, "w") as handle:
            handle.write("signatures: []\n")
        proc = subprocess.run(
            [sys.executable, RENDERER, "--store", store_path, "--out", out_path],
            capture_output=True, text=True,
        )
        check("[%s] empty store exits non-zero" % RUNTIME, proc.returncode != 0, proc.stdout + proc.stderr)
        check("[%s] empty store writes no file" % RUNTIME, not os.path.exists(out_path))


def test_disabled_variant():
    """Assert a disabled variant is reported with its reason instead of being rendered.

    This is the "refuse, do not silently no-op" gate: the reason recorded in the store has to
    reach the generated file so an operator can tell a reviewed skip from a missing rule.
    """
    store = """
signatures:
  - id: CVE-0000-0000
    variants:
      - name: off_variant
        enabled: false
        disabled_reason: "kept off until header capture exists"
        match:
          uri_regex: "^/never$"
"""
    with tempfile.TemporaryDirectory() as workdir:
        text = render_text(store, workdir)
        check("[%s] all-disabled store exits non-zero" % RUNTIME, text is None)

    # Same variant enabled: it must appear, and the disabled section must be absent.
    enabled = store.replace("enabled: false\n        ", "")
    with tempfile.TemporaryDirectory() as workdir:
        text = render_text(enabled, workdir)
        check("[%s] enabled variant renders" % RUNTIME, text is not None)
        if text is not None:
            check("[%s] rendered line present" % RUNTIME,
                  'SetEnvIf Request_URI "^/never$" tarpit-sig=CVE-0000-0000/off_variant' in text)
            check("[%s] no skip section" % RUNTIME, "skipped variants" not in text)


def test_backend_override():
    """Assert the proxy target is a parameter, not a hard-coded loopback.

    The same generated file has to target the native responder today and the Stage 2 gateway
    later, so a hard-coded backend would silently pin Profile A to the responder.
    """
    with tempfile.TemporaryDirectory() as workdir:
        text = render_text(open(STORE).read(), workdir, backend="http://127.0.0.1:8443")
        if text is not None:
            check("[%s] backend override honoured" % RUNTIME,
                  "RewriteRule ^(.*)$ http://127.0.0.1:8443$1 [P,L]" in text)


def load_renderer():
    """Import the renderer as a module so its pure functions can be unit-tested directly.

    The file is not an importable package name (hyphenated), so it is loaded by path. Shell
    invocation still covers the CLI contract; importing is what lets a single regex be
    assessed without building a whole store around it.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("render_signature_rules", RENDERER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_redos_gate():
    """Assert the Bundle L3 gate flags catastrophic-backtracking shapes and passes real ones.

    The gate exists because a signature regex is copied into every vhost that includes the
    generated file and is evaluated per request, so one pathological pattern costs every
    client. The test pins both directions: the classic bad shapes must be flagged, and the
    patterns actually shipped must not be, otherwise the gate is either decorative or a
    permanent blocker.
    """
    mod = load_renderer()

    bad = [
        "^(a+)+$",              # quantified group inside a quantifier - exponential
        "^(a|ab)+$",            # overlapping alternation under a quantifier
        "^.*.*$",               # two adjacent unbounded wildcards
        "^(x{2,})+$",           # counted repetition inside a quantifier
        "^" + "a" * (mod.MAX_REGEX_LENGTH + 1) + "$",   # over the length ceiling
    ]
    for pattern in bad:
        risk, reason = mod.redos_assessment(pattern)
        check("[%s] flags %s" % (RUNTIME, pattern), risk, reason or "no reason returned")

    good = [
        "^/h2probe-[0-9]{1,8}$",
        "^/wp-admin/$",
        r"^/\.env$",
        "^/(?:admin|manager)/index\\.php$",
    ]
    for pattern in good:
        risk, reason = mod.redos_assessment(pattern)
        check("[%s] accepts %s" % (RUNTIME, pattern), not risk, reason)

    # Every regex the project ships must clear the gate, or the gate blocks the shipped file.
    with open(STORE) as handle:
        store_text = handle.read()
    for pattern in re.findall(r"uri_regex:\s*\"?([^\"'\n]+)\"?", store_text):
        risk, reason = mod.redos_assessment(pattern.strip())
        check("[%s] shipped regex clears the gate: %s" % (RUNTIME, pattern.strip()), not risk, reason)

    # A store whose only variant is flagged renders nothing, so the CLI refuses; with
    # --allow-redos the same store renders and the override is announced on stderr.
    with tempfile.TemporaryDirectory() as workdir:
        store_path = os.path.join(workdir, "signatures.yaml")
        out_path = os.path.join(workdir, "tarpit-signatures.conf")
        with open(store_path, "w") as handle:
            handle.write("signatures:\n  - id: CVE-0000-0001\n    variants:\n"
                         "      - name: risky\n        tier: ['1']\n        match:\n"
                         "          uri_regex: \"^(a+)+$\"\n")
        refused = subprocess.run([sys.executable, RENDERER, "--store", store_path, "--out", out_path],
                                 capture_output=True, text=True)
        check("[%s] flagged-only store is refused" % RUNTIME, refused.returncode != 0,
              refused.stdout + refused.stderr)
        check("[%s] refused store writes no file" % RUNTIME, not os.path.exists(out_path))

        allowed = subprocess.run([sys.executable, RENDERER, "--store", store_path,
                                  "--out", out_path, "--allow-redos"],
                                 capture_output=True, text=True)
        check("[%s] --allow-redos renders it" % RUNTIME, allowed.returncode == 0,
              allowed.stdout + allowed.stderr)
        check("[%s] the override is announced" % RUNTIME,
              "--allow-redos" in (allowed.stderr + allowed.stdout) and "ReDoS" in (allowed.stderr + allowed.stdout))


def main():
    """Run every renderer check on this interpreter and print a summary.

    Skips with exit 0 when PyYAML is missing: the renderer needs it, and on this host PyYAML
    exists for python3.9 only, so a python3.12 run would otherwise report a false failure for
    an environment fact rather than a code defect.
    """
    probe = subprocess.run([sys.executable, "-c", "import yaml"], capture_output=True, text=True)
    if probe.returncode != 0:
        print("SKIP checks: PyYAML is not importable by %s" % sys.executable)
        return 0
    test_real_store()
    test_redos_gate()
    test_empty_store()
    test_disabled_variant()
    test_backend_override()
    if failures:
        for failure in failures:
            print("FAIL", failure)
        print("FAIL checks: %d passed, %d failed" % (checks - len(failures), len(failures)))
        return 1
    print("PASS checks: %d passed, 0 failed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
