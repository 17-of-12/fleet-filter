#!/usr/bin/env python3
"""Tests for `bin/webtree-audit.py` - the Stage 4 file-shape analyzer (Bundle Z tiers 1-3).

These exist because the analyzer is a scorer, and a scorer without tests drifts silently: change one
weight and every verdict moves without anything failing. The expectations below are **measured**
values (recorded 2026-11-16 against the fixtures defined here), asserted as floors rather than
exact numbers so a weight increase does not break the suite while a regression does.

Covered: the metric primitives (entropy, encoded-literal runs, line density, magic-vs-extension,
dangerous-function counting, variable-function calls), the two operational guarantees (a real page
is clean, a shell is flagged), the incremental state machine the owner asked for (new/changed/reused/
removed, `--full`, `--full-every-hours`), allowlisting, the report shape, and the CLI exit codes.

Runs under Python 3.9 and 3.12. PHP tokenisation checks skip when no php binary exists, because the
analyzer is designed to degrade rather than fail on hosts without PHP.
"""

from __future__ import print_function

import base64
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

SPEC = importlib.util.spec_from_file_location("webtree_audit",
                                              os.path.join(ROOT, "bin", "webtree-audit.py"))
wa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wa)

PASS = 0
FAIL = 0

# A page that exists on a real site: markup, low entropy, no dangerous functions. Measured score 0.
CLEAN_HTML = (b'<!DOCTYPE html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n'
              b'  <title>University Portal</title>\n</head>\n<body>\n  <h1>Applicant Portal</h1>\n'
              b'  <p>Sign in to continue.</p>\n</body>\n</html>\n')
# A small shell: one statement, base64 payload, a variable-function call and an eval. Measured 5.
SHELL_SMALL = (b'<?php $q=base64_decode("'
               b'Q29uZmlndXJlZCBzeXN0ZW0gY29tbWFuZCBleGVjdXRlZCBzdWNjZXNzZnVsbHkgYW5kIHJldHVybmVk'
               b'IHRvIHRoZSBjbGllbnQ' + b'"); $f="sys"."tem"; ${f}($q); @eval($q); ?>')
# The same idea rewritten so no string signature matches it: longer payload, rot13'd helper name.
# Measured 4 - tier 1 alone lands on `review`; a tier-2 yara hit (+5) is what promotes it.
_OBF_PAYLOAD = ("if(isset($_POST['cmd'])){$out=array();exec($_POST['cmd'],$out);"
                "echo implode(\"\\n\",$out);}elseif(isset($_GET['x'])){readfile($_GET['x']);}"
                "else{phpinfo();}")
SHELL_OBF = ('<?php $z=' + base64.b64encode((_OBF_PAYLOAD * 3).encode()).decode() +
             '; $f=str_rot13("rfgre"); $a="eval"; $a($z); ?>').encode()
# PHP body shipped with an image extension. Measured 6 and the mismatch reason is stated.
HIDDEN_PNG = b'<?php $x=base64_decode("Zm9vYmFyYmF6"); eval($x); ?>'


def check(condition, label, detail=""):
    """Record one assertion and print it, accumulating instead of raising on the first failure."""
    global PASS, FAIL
    if condition:
        PASS += 1
        print("ok   %s" % label)
    else:
        FAIL += 1
        print("FAIL %s %s" % (label, detail))


def write(work, relpath, data):
    """Write `data` to `relpath` under `work` and return the full path."""
    path = os.path.join(work, relpath)
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def test_entropy():
    """Entropy must separate uniform bytes, text, and encoded payloads."""
    check(wa.shannon_entropy(b"") == 0.0, "empty input has zero entropy")
    check(wa.shannon_entropy(b"A" * 500) == 0.0, "one repeated byte has zero entropy")
    text = wa.shannon_entropy(CLEAN_HTML)
    packed = wa.shannon_entropy(bytes(bytearray(range(256))) * 4)
    check(4.0 < text < 6.0, "markup entropy lands in the text range", "%.3f" % text)
    check(packed > 7.9, "a full byte alphabet approaches 8 bits", "%.3f" % packed)
    check(text < packed, "markup scores lower than an encoded payload")


def test_literal_runs():
    """Base64 and hex literals are measured by their longest run, not their total volume."""
    check(wa.longest_base64_run(b"no literals here at all") == 0, "short word runs are ignored")
    run = b"Q29uZmlndXJlZCBzeXN0ZW0gY29tbWFuZCBleGVjdXRlZCBzdWNjZXNzZnVsbHk="
    check(wa.longest_base64_run(b'x = "' + run + b'";') == len(run), "the base64 run is measured",
          str(wa.longest_base64_run(run)))
    check(wa.longest_base64_run(b"a" * 10) == 0, "a 10-char run is below the 24-char floor")
    check(wa.longest_hex_run(b"0x" + b"ab" * 30) == 62, "a long hex literal is measured",
          str(wa.longest_hex_run(b"0x" + b"ab" * 30)))
    check(wa.longest_hex_run(b"deadbeef") == 0, "an 8-char hex value is below the 48-char floor")


def test_line_density():
    """Bytes-per-line is the minification proxy: one line of 100 bytes scores 100.0."""
    check(wa.bytes_per_line(b"abc\ndef\n") == 4.0, "two 3-byte lines average 4.0 (trailing newline "
          "ends the last line rather than starting one)")
    check(wa.bytes_per_line(b"x" * 100) == 100.0, "a single 100-byte line averages 100.0")
    check(wa.bytes_per_line(b"") == 0.0, "empty input reports 0.0")


def test_magic_and_extension():
    """Extension and content must agree; the mismatch is the finding that hides a shell."""
    check(wa.detect_magic(b"\x89PNG\r\n\x1a\nrest") == "png", "PNG header is detected")
    check(wa.detect_magic(b"%PDF-1.4") == "pdf", "PDF header is detected")
    check(wa.detect_magic(b"<html><body>x</body></html>") == "html", "html is detected")
    check(wa.detect_magic(b"just text") is None, "unrecognised bytes report no type")
    check(wa.extension_of("a/b.File.PHP") == "php", "extension case is normalised")
    check(wa.extension_of("Makefile") == "", "a file with no extension returns an empty string")
    check(wa.magic_mismatch("x.png", b"\x89PNG\r\n\x1a\ndata") is None,
          "a real png named .png does not mismatch")
    mismatch = wa.magic_mismatch("x.png", b"<?php echo 1; ?>")
    check(bool(mismatch) and "png" in mismatch, "a php body inside .png is a mismatch", str(mismatch))
    check(bool(wa.magic_mismatch("x.php", b"\x89PNG\r\n\x1a\ndata")),
          "a png body inside .php is a mismatch")


def test_function_census():
    """Dangerous functions are counted on word boundaries so `evaluate(` is not `eval(`."""
    found = wa.dangerous_functions(b"<?php evaluate($x); eval($y); base64_decode($z); ?>")
    check(found.get("eval") == 1, "`eval(` is counted once", str(found))
    check("evaluate" not in found, "`evaluate(` is not mistaken for eval", str(found))
    check(found.get("base64_decode") == 1, "base64_decode is counted as medium risk", str(found))
    check(wa.dangerous_functions(b"<html>nothing</html>") == {}, "markup has no dangerous functions")
    check(wa.variable_function_calls(b'$f(); ${"sys"."tem"}($x);') == 2,
          "both variable-function call shapes are counted")
    check(wa.variable_function_calls(b"foo(); bar();") == 0, "normal calls are not variable calls")


def test_php_tokens():
    """When PHP exists, real tokenisation replaces regex guessing; otherwise it degrades to None."""
    if not os.path.exists("/usr/bin/php"):
        print("skip php tokenisation (no /usr/bin/php)")
        return
    with tempfile.TemporaryDirectory() as work:
        path = write(work, "shell.php", b'<?php eval("phpinfo();"); ?>')
        stats = wa.php_token_stats(path, "/usr/bin/php")
        check(stats is not None, "php tokenisation returns a result when php exists")
        if stats:
            check(stats["eval"] == 1, "T_EVAL is counted from the real token stream", str(stats))
            check(stats["tokens"] > 3, "the token count is plausible", str(stats))
        check(wa.php_token_stats(path, "/nonexistent/php") is None,
              "a missing php binary degrades to None instead of failing")


def test_scoring_guarantees():
    """The two operational guarantees, asserted against measured floors."""
    with tempfile.TemporaryDirectory() as work:
        html = write(work, "index.html", CLEAN_HTML)
        small = write(work, "small.php", SHELL_SMALL)
        obf = write(work, "obf.php", SHELL_OBF)
        hidden = write(work, "logo.png", HIDDEN_PNG)

        clean = wa.audit_file(html)
        check(clean["verdict"] == "clean" and clean["score"] == 0,
              "a normal HTML page scores 0 and is clean", str(clean["score"]))

        small_record = wa.audit_file(small)
        check(small_record["score"] >= wa.DEFAULT_REVIEW_SCORE,
              "a small shell reaches the review threshold",
              "score=%s reasons=%s" % (small_record["score"], small_record["reasons"]))
        check(small_record["verdict"] in ("review", "quarantine"), "the small shell is flagged",
              small_record["verdict"])
        check(any("eval" in r for r in small_record["reasons"]),
              "the reason names the eval call", str(small_record["reasons"]))

        obf_record = wa.audit_file(obf)
        check(obf_record["score"] >= wa.DEFAULT_REVIEW_SCORE,
              "an LLM-style rewrite of the same shell still scores (structure, not strings)",
              "score=%s reasons=%s" % (obf_record["score"], obf_record["reasons"]))
        check(obf_record["longest_base64"] > 500, "the rewritten payload's run is still measured",
              str(obf_record["longest_base64"]))

        hidden_record = wa.audit_file(hidden)
        check(hidden_record["score"] >= wa.DEFAULT_REVIEW_SCORE,
              "a php body shipped as .png reaches the review threshold",
              "score=%s" % hidden_record["score"])
        check(any("png" in r for r in hidden_record["reasons"]),
              "the mismatch reason is stated in the record", str(hidden_record["reasons"]))

        # tier 2 is what promotes a known-bad file: a yara hit adds 5 points, so the same shape that
        # scored `review` becomes `quarantine`. Assert the promotion rule, not just the arithmetic.
        promoted = wa.verdict_for(wa.DEFAULT_REVIEW_SCORE + 5)
        check(promoted == "quarantine", "a yara hit (+5) promotes a review file to quarantine",
              promoted)

    check(wa.verdict_for(0) == "clean" and wa.verdict_for(4) == "review"
          and wa.verdict_for(8) == "quarantine", "default thresholds map as documented")
    check(wa.verdict_for(5, 10, 20) == "clean" and wa.verdict_for(15, 10, 20) == "review",
          "custom thresholds are honoured")


def test_incremental_state():
    """The owner's cadence rule: audit new/changed files, reuse the rest, rescan weekly or on --full."""
    with tempfile.TemporaryDirectory() as work:
        tree = os.path.join(work, "webroot")
        state = os.path.join(work, "state.json")
        write(tree, "index.html", CLEAN_HTML)

        first = wa.audit(tree, state_path=state)
        check(first["mode"] == "full", "the first run is a full scan (no prior state)", first["mode"])
        check(first["new_files"] == 1 and first["files_audited"] == 1,
              "the only file is reported as new", str(first["new_files"]))

        second = wa.audit(tree, state_path=state)
        check(second["mode"] == "incremental", "a later run is incremental", second["mode"])
        check(second["files_audited"] == 0 and second["reused_files"] == 1,
              "an unchanged file is reused, not re-read",
              "audited=%s reused=%s" % (second["files_audited"], second["reused_files"]))
        check(second["summary"]["clean"] == 1, "the reused verdict is carried forward",
              str(second["summary"]))

        write(tree, "small.php", SHELL_SMALL)
        third = wa.audit(tree, state_path=state)
        check(third["new_files"] == 1 and third["changed_files"] == 0 and third["reused_files"] == 1,
              "only the new file is audited; the old one is reused",
              "new=%s changed=%s reused=%s" % (third["new_files"], third["changed_files"],
                                               third["reused_files"]))
        check(third["summary"]["review"] == 1 and third["summary"]["clean"] == 1,
              "the new file's verdict appears alongside the carried-forward one",
              str(third["summary"]))

        write(tree, "small.php", SHELL_SMALL + b"\n// touched\n")
        fourth = wa.audit(tree, state_path=state)
        check(fourth["changed_files"] == 1 and fourth["new_files"] == 0,
              "a modified file is re-audited and counted as changed",
              "changed=%s new=%s" % (fourth["changed_files"], fourth["new_files"]))

        forced = wa.audit(tree, state_path=state, full=True)
        check(forced["mode"] == "full" and forced["reused_files"] == 0,
              "--full re-audits everything", "%s/%s" % (forced["mode"], forced["reused_files"]))

        os.remove(os.path.join(tree, "small.php"))
        gone = wa.audit(tree, state_path=state, full=True)
        check(gone["removed_files"] == 1 and gone["summary"]["removed"] == 1,
              "a file that disappears is reported, not silently dropped",
              "removed=%s summary=%s" % (gone["removed_files"], gone["summary"]))

        # cadence: a state whose last full scan is old forces a full run; a fresh one does not.
        aged = dict(json.load(open(state)))
        aged["last_full_scan"] = 0
        with open(state, "w") as handle:
            json.dump(aged, handle)
        stale = wa.audit(tree, state_path=None, full_every_hours=168, now=10 ** 9)
        check(stale["mode"] == "full", "a full scan older than the interval is forced", stale["mode"])
        fresh_state = os.path.join(work, "fresh.json")
        with open(fresh_state, "w") as handle:
            json.dump({"files": {}, "last_full_scan": 10 ** 9}, handle)
        fresh = wa.audit(tree, state_path=fresh_state, full_every_hours=168, now=10 ** 9 + 3600)
        check(fresh["mode"] == "incremental", "a recent full scan keeps the run incremental",
              fresh["mode"])


def test_discovery_and_allowlist():
    """Discovery must skip symlinks, respect a limit, and honour the allowlist."""
    with tempfile.TemporaryDirectory() as work:
        write(work, "a.html", CLEAN_HTML)
        write(work, "b.html", CLEAN_HTML)
        write(work, "sub/c.php", b"<?php echo 1; ?>")
        os.symlink(os.path.join(work, "a.html"), os.path.join(work, "link.html"))

        found = list(wa.discover_files(work))
        check(len(found) == 3, "three real files are found", str(found))
        check(all("link.html" not in p for p in found), "the symlink is skipped by default")
        check(len(list(wa.discover_files(work, limit=2))) == 2, "the limit is enforced")
        check(list(wa.discover_files(os.path.join(work, "a.html")))
              == [os.path.join(work, "a.html")], "a single file path audits just that file")
        check(len(list(wa.discover_files(work, follow_symlinks=True))) == 4,
              "symlinks are included when explicitly followed")

        allowlist = os.path.join(work, "allowlist")
        with open(allowlist, "w") as handle:
            handle.write("# known-good\n\n%s\n%s\n" % (os.path.join(work, "a.html"),
                                                       os.path.join(work, "sub")))
        entries = wa.load_allowlist(allowlist)
        check(len(entries) == 2, "comments and blanks are ignored", str(entries))
        check(wa.is_allowlisted(os.path.join(work, "a.html"), entries), "exact path is allowlisted")
        check(wa.is_allowlisted(os.path.join(work, "sub/c.php"), entries),
              "a file under an allowlisted directory is suppressed")
        check(not wa.is_allowlisted(os.path.join(work, "b.html"), entries),
              "an unlisted file is not suppressed")


def test_allowlist_entry_forms():
    """Absolute, root-relative, and bare-directory-name entries must all suppress correctly.

    The first audit of build01's real docroot quarantined 57 files and all of them were Composer
    dependencies under a `vendor/` directory. Absolute-only matching could not express "any vendor
    tree" without naming every app, so the matcher gained the other two forms; this test pins all
    three plus the boundary rule that stops `/app` from matching `/application.html`.
    """
    with tempfile.TemporaryDirectory() as work:
        root = os.path.join(work, "www")
        write(work, "www/app/index.php", b"<?php echo 1; ?>")
        write(work, "www/app/vendor/x.php", b"<?php echo 1; ?>")
        write(work, "www/vendor/y.php", b"<?php echo 1; ?>")
        write(work, "www/app/node_modules/z.js", b"var a=1;")
        write(work, "www/application.html", CLEAN_HTML)
        write(work, "www/legacy/bundles/cache.php", b"<?php echo 1; ?>")

        entries = wa.parse_allowlist("vendor/\nnode_modules/\nlegacy/bundles\n")
        check(wa.is_allowlisted(os.path.join(root, "app/vendor/x.php"), entries, root=root),
              "a file under a bare-name vendor directory is suppressed")
        check(wa.is_allowlisted(os.path.join(root, "vendor/y.php"), entries, root=root),
              "a vendor directory anywhere under the root is suppressed")
        check(wa.is_allowlisted(os.path.join(root, "app/node_modules/z.js"), entries, root=root),
              "node_modules is suppressed the same way")
        check(wa.is_allowlisted(os.path.join(root, "legacy/bundles/cache.php"), entries, root=root),
              "a root-relative entry suppresses everything under that directory")
        check(not wa.is_allowlisted(os.path.join(root, "application.html"), entries, root=root),
              "a prefix must end at a path boundary; app does not match application.html")
        check(not wa.is_allowlisted(os.path.join(root, "app/index.php"), entries, root=root),
              "an ordinary app file is still audited")

        # A relative entry with no root falls back to the working directory, which is how the
        # pre-root parameterisation behaved; existing deployments must not change verdicts.
        cwd_entries = wa.parse_allowlist("app/vendor\n")
        check(wa.is_allowlisted(os.path.join(os.getcwd(), "app/vendor/x.php"), cwd_entries),
              "a relative entry still resolves against cwd when no root is supplied")


def test_report_and_cli():
    """The report shape, the text rendering, and the exit codes a timer or CI would consume."""
    with tempfile.TemporaryDirectory() as work:
        tree = os.path.join(work, "webroot")
        write(tree, "index.html", CLEAN_HTML)
        write(tree, "small.php", SHELL_SMALL)
        report = wa.audit(tree, state_path=os.path.join(work, "s.json"))
        check(report["files_audited"] == 2, "both files appear in the report",
              str(report["files_audited"]))
        check(report["summary"]["review"] == 1 and report["summary"]["clean"] == 1,
              "summary counts match the records", str(report["summary"]))
        check(os.path.isabs(report["root"]) and bool(report["generated_at"]),
              "the report records an absolute root and a timestamp")

        text = wa.render_text(report)
        check("webtree audit" in text and "small.php" in text and "changes:" in text,
              "the text render names the flagged file and the change counts")

        json_out = os.path.join(work, "report.json")
        code = wa.main([tree, "--json", json_out, "--state", os.path.join(work, "cli.json"),
                        "--quiet"])
        check(code == 10, "exit code 10 when something needs review", str(code))
        with open(json_out) as handle:
            written = json.load(handle)
        check(written["files_audited"] == 2, "the JSON file holds the same report")

        clean_only = os.path.join(work, "clean")
        write(clean_only, "index.html", CLEAN_HTML)
        check(wa.main([clean_only, "--state", os.path.join(work, "clean.json"), "--quiet"]) == 0,
              "exit code 0 when nothing is flagged")

        check(wa.run_yara(os.path.join(tree, "index.html"), os.path.join(work, "missing.yar"))
              is None, "a missing ruleset degrades tier 2 to None rather than failing")


def test_yara_output_parsing():
    """yara reports `RULE FILE` per line; the report must carry the rule name, not the path."""
    check(wa.parse_yara_matches("EICAR_TestFile /var/www/html/eicar.txt") == ["EICAR_TestFile"],
          "a plain match line yields the rule name", str(wa.parse_yara_matches("EICAR_TestFile /x")))
    check(wa.parse_yara_matches("default:PHP_Sink_On_Superglobal /a.php")
          == ["PHP_Sink_On_Superglobal"], "a namespaced rule name is unwrapped")
    check(wa.parse_yara_matches(
        "PHP_Sink_On_Superglobal /a.php\nPHP_Base64_Decode_Eval /a.php\n")
          == ["PHP_Sink_On_Superglobal", "PHP_Base64_Decode_Eval"], "every match line is kept")
    check(wa.parse_yara_matches("") == [], "no output means no rules")
    check(wa.parse_yara_matches("\n\n") == [], "blank lines are ignored")


def main():
    """Run every analyzer test group and exit non-zero if any check regressed."""
    for group in (test_entropy, test_literal_runs, test_line_density, test_magic_and_extension,
                  test_function_census, test_php_tokens, test_scoring_guarantees,
                  test_incremental_state, test_discovery_and_allowlist,
                  test_allowlist_entry_forms, test_report_and_cli,
                  test_yara_output_parsing):
        group()
    print("test_webtree_audit.py: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


main()
