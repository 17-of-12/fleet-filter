#!/usr/bin/env python3
"""Tests for bin/webtree-quarantine.py (Bundle Z7).

Z7's requirement is not "move the file", it is "move the file and be able to undo it", so these
tests are written around reversibility: every apply is followed by a restore and a byte-for-byte
comparison. The refusals are tested with the same weight as the successes, because the failure mode
that matters operationally is the tool moving something it should not have.

Run directly (`python3.9 tests/unit/test_webtree_quarantine.py`) the way bin/check.sh runs suites.
"""

import json
import os
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(REPO_ROOT, "bin", "webtree-quarantine.py")

sys.path.insert(0, os.path.dirname(SCRIPT))
import importlib.util  # noqa: E402  (imported after sys.path is set for the module load)

_spec = importlib.util.spec_from_file_location("webtree_quarantine", SCRIPT)
wq = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wq)

PASS = 0
FAIL = 0
PAYLOAD = b"<?php eval($_GET[0]); ?>"


def check(condition, message, detail=""):
    """Record one assertion result."""
    global PASS, FAIL
    if condition:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL %s %s" % (message, detail))


def build_docroot(work, extra=None):
    """Create a docroot containing one clean file and one webshell, plus optional extra files.

    Returns `(docroot, report_path, journal_path, shell_path)`.
    """
    docroot = os.path.join(work, "www")
    os.makedirs(os.path.join(docroot, "uploads"))
    clean = os.path.join(docroot, "index.php")
    shell = os.path.join(docroot, "uploads", "shell.php")
    with open(clean, "wb") as handle:
        handle.write(b"<?php echo 'home'; ?>\n")
    with open(shell, "wb") as handle:
        handle.write(PAYLOAD)
    records = []
    for path, verdict, score in ([(clean, "clean", 0), (shell, "quarantine", 12)]
                                 + list(extra or [])):
        records.append({"path": path, "verdict": verdict, "score": score,
                        "sha256": wq.sha256_file(path)})
    report_path = os.path.join(work, "report.json")
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump({"generated_at": int(time.time()), "root": docroot, "files": records}, handle)
    return docroot, report_path, os.path.join(work, "quarantine.json"), shell


def test_dry_run_moves_nothing():
    """A run without --apply must report the plan and leave the docroot untouched."""
    with tempfile.TemporaryDirectory() as work:
        docroot, report, journal, shell = build_docroot(work)
        results = wq.quarantine(report, docroot, quarantine_dir=os.path.join(work, "holding"),
                                journal_path=journal, apply_changes=False)
        check(len(results) == 1, "only the quarantined file is planned", str(results))
        check(results[0]["action"] == "would-quarantine", "dry run reports would-quarantine",
              str(results[0]))
        check(os.path.isfile(shell), "dry run left the file in the docroot")
        check(not os.path.exists(journal), "dry run wrote no journal")


def test_apply_and_restore_round_trip():
    """The core guarantee: apply moves the file, restore puts the same bytes back."""
    with tempfile.TemporaryDirectory() as work:
        docroot, report, journal, shell = build_docroot(work)
        holding_root = os.path.join(work, "holding")
        results = wq.quarantine(report, docroot, quarantine_dir=holding_root,
                                journal_path=journal, apply_changes=True)
        check(results[0]["action"] == "quarantined", "apply quarantined the file", str(results[0]))
        check(not os.path.exists(shell), "the file left the docroot")
        held = os.path.join(holding_root, "uploads", "shell.php")
        check(os.path.isfile(held), "the file is held under its relative path", held)
        with open(held, "rb") as handle:
            check(handle.read() == PAYLOAD, "the held copy is byte-identical")

        entries = json.load(open(journal))["entries"]
        check(len(entries) == 1 and entries[0]["action"] == "quarantined",
              "the journal records the quarantine", str(entries))

        restored = wq.restore(shell, journal_path=journal)
        check(os.path.normpath(restored) == os.path.normpath(shell), "restore returns the origin")
        with open(shell, "rb") as handle:
            check(handle.read() == PAYLOAD, "the restored file is byte-identical")
        check(not os.path.exists(held), "the held copy was consumed by the restore")
        actions = [e["action"] for e in json.load(open(journal))["entries"]]
        check(actions == ["quarantined", "restored"], "journal shows both halves", str(actions))


def test_changed_content_is_refused():
    """A file that changed since the audit must be refused, not quarantined on trust."""
    with tempfile.TemporaryDirectory() as work:
        docroot, report, journal, shell = build_docroot(work)
        with open(shell, "wb") as handle:
            handle.write(b"<?php eval($_GET[0]); /* mutated */ ?>")
        results = wq.quarantine(report, docroot, quarantine_dir=os.path.join(work, "holding"),
                                journal_path=journal, apply_changes=True)
        check(results[0]["action"] == "refused", "changed content is refused", str(results[0]))
        check("changed since the audit" in results[0]["detail"], "the refusal says why",
              results[0]["detail"])
        check(os.path.isfile(shell), "a refused file stays in the docroot")
        check(not os.path.exists(journal), "a refused quarantine is not journaled")


def test_missing_and_already_held_are_reported_not_duplicated():
    """Missing files are reported; a second apply must not create a second journal entry."""
    with tempfile.TemporaryDirectory() as work:
        docroot, report, journal, shell = build_docroot(work)
        holding_root = os.path.join(work, "holding")
        wq.quarantine(report, docroot, quarantine_dir=holding_root, journal_path=journal,
                      apply_changes=True)
        second = wq.quarantine(report, docroot, quarantine_dir=holding_root,
                               journal_path=journal, apply_changes=True)
        check(second[0]["action"] == "skipped", "a held file is skipped on re-apply",
              str(second[0]))
        check(len(json.load(open(journal))["entries"]) == 1, "no duplicate journal entry")

        os.remove(os.path.join(holding_root, "uploads", "shell.php"))
        with open(shell, "wb") as handle:
            handle.write(PAYLOAD)
        third = wq.quarantine(report, docroot, quarantine_dir=holding_root,
                              journal_path=journal, apply_changes=False)
        check(third[0]["action"] == "skipped", "the still-flagged file is still recognised as held")


def test_missing_source_file_is_reported():
    """A flagged file that no longer exists is reported `missing`, not moved or crashed on."""
    with tempfile.TemporaryDirectory() as work:
        docroot = os.path.join(work, "www")
        os.makedirs(docroot)
        gone = os.path.join(docroot, "gone.php")
        with open(gone, "wb") as handle:
            handle.write(PAYLOAD)
        digest = wq.sha256_file(gone)
        os.remove(gone)
        report = os.path.join(work, "report.json")
        with open(report, "w", encoding="utf-8") as handle:
            json.dump({"files": [{"path": gone, "verdict": "quarantine", "score": 9,
                                  "sha256": digest}]}, handle)
        results = wq.quarantine(report, docroot, quarantine_dir=os.path.join(work, "holding"),
                                journal_path=os.path.join(work, "journal.json"),
                                apply_changes=True)
        check(results[0]["action"] == "missing", "a vanished file is reported missing",
              str(results[0]))


def test_path_outside_docroot_is_refused():
    """The holding path is derived from the docroot; a path outside it cannot be placed."""
    with tempfile.TemporaryDirectory() as work:
        docroot = os.path.join(work, "www")
        os.makedirs(docroot)
        try:
            wq.holding_path(docroot, os.path.join(work, "holding"), "/etc/passwd")
        except ValueError as exc:
            check("not inside docroot" in str(exc), "outside paths are refused", str(exc))
        else:
            check(False, "holding_path accepted a path outside the docroot")


def test_review_verdicts_are_opt_in():
    """`review` files are only eligible when the operator asks for them."""
    with tempfile.TemporaryDirectory() as work:
        docroot = os.path.join(work, "www")
        os.makedirs(docroot)
        review_file = os.path.join(docroot, "suspicious.inc")
        with open(review_file, "wb") as handle:
            handle.write(b"<?php gzundecode($x); ?>")
        report = os.path.join(work, "report.json")
        with open(report, "w", encoding="utf-8") as handle:
            json.dump({"files": [{"path": review_file, "verdict": "review", "score": 6,
                                  "sha256": wq.sha256_file(review_file)}]}, handle)
        journal = os.path.join(work, "journal.json")
        check(wq.quarantine(report, docroot, quarantine_dir=os.path.join(work, "holding"),
                            journal_path=journal, apply_changes=False) == [],
              "a review-only report quarantines nothing by default")
        results = wq.quarantine(report, docroot, quarantine_dir=os.path.join(work, "holding"),
                                journal_path=journal, apply_changes=False,
                                verdicts=("quarantine", "review"))
        check(len(results) == 1 and results[0]["action"] == "would-quarantine",
              "--include-review makes review files eligible", str(results))


def test_corrupt_journal_is_refused():
    """A journal that is not a journal must fail loudly rather than be replaced."""
    with tempfile.TemporaryDirectory() as work:
        journal = os.path.join(work, "quarantine.json")
        with open(journal, "w", encoding="utf-8") as handle:
            handle.write("[1, 2, 3]\n")
        try:
            wq.load_journal(journal)
        except ValueError as exc:
            check("not a quarantine journal" in str(exc), "a malformed journal is refused",
                  str(exc))
        else:
            check(False, "load_journal accepted a malformed journal")


def test_multiple_files_keep_their_tree_shape():
    """Quarantining several files preserves each file's position under the holding root."""
    with tempfile.TemporaryDirectory() as work:
        docroot = os.path.join(work, "www")
        os.makedirs(os.path.join(docroot, "a"))
        os.makedirs(os.path.join(docroot, "b"))
        records = []
        for relative in ("a/x.php", "b/y.php", "z.php"):
            path = os.path.join(docroot, relative)
            with open(path, "wb") as handle:
                handle.write(PAYLOAD)
            records.append({"path": path, "verdict": "quarantine", "score": 11,
                            "sha256": wq.sha256_file(path)})
        report = os.path.join(work, "report.json")
        with open(report, "w", encoding="utf-8") as handle:
            json.dump({"files": records}, handle)
        holding_root = os.path.join(work, "holding")
        results = wq.quarantine(report, docroot, quarantine_dir=holding_root,
                                journal_path=os.path.join(work, "journal.json"),
                                apply_changes=True)
        check(len(results) == 3, "all three files were processed", str(len(results)))
        for relative in ("a/x.php", "b/y.php", "z.php"):
            check(os.path.isfile(os.path.join(holding_root, relative)),
                  "%s is held at its relative path" % relative)
        check(not os.listdir(docroot) or all(
            not os.path.isfile(os.path.join(dp, f))
            for dp, _d, fs in os.walk(docroot) for f in fs), "the docroot is empty of files")


def test_holding_path_versions_an_existing_target():
    """A holding path that already exists is suffixed rather than overwritten.

    `quarantine()` refuses to double-hold a source it already holds, so this branch is reached when
    the holding root is shared (two docroots, or a journal that was rebuilt): the previous
    generation must survive, because the journal's only proof of the earlier bytes is that file.
    """
    with tempfile.TemporaryDirectory() as work:
        docroot = os.path.join(work, "www")
        os.makedirs(docroot)
        with open(os.path.join(docroot, "x.php"), "wb") as handle:
            handle.write(PAYLOAD)
        holding_root = os.path.join(work, "holding")
        os.makedirs(holding_root)
        with open(os.path.join(holding_root, "x.php"), "wb") as handle:
            handle.write(b"previous generation")
        # An unused holding path is taken as-is.
        unused = wq.holding_path(docroot, holding_root, os.path.join(docroot, "fresh.php"))
        check(unused == os.path.join(holding_root, "fresh.php"),
              "an unused holding path is used as-is", unused)
        # An occupied one is stamped: with an explicit stamp, that stamp; without one, the clock.
        second = wq.holding_path(docroot, holding_root, os.path.join(docroot, "x.php"),
                                 stamp="20261116T120000Z")
        check(second == os.path.join(holding_root, "x.php.20261116T120000Z"),
              "an occupied holding path gains the stamp instead of overwriting", second)
        auto = wq.holding_path(docroot, holding_root, os.path.join(docroot, "x.php"))
        check(auto.startswith(os.path.join(holding_root, "x.php.")) and auto != second,
              "without an explicit stamp the clock value is used", auto)
        with open(os.path.join(holding_root, "x.php"), "rb") as handle:
            check(handle.read() == b"previous generation", "the earlier generation is untouched")


def test_cli_dry_run_and_apply():
    """The CLI must work end to end and exit 0 for both modes."""
    with tempfile.TemporaryDirectory() as work:
        docroot, report, journal, shell = build_docroot(work)
        holding_root = os.path.join(work, "holding")
        common = ["--report", report, "--docroot", docroot,
                  "--quarantine-dir", holding_root, "--journal", journal]
        dry = subprocess.run([sys.executable, SCRIPT] + common,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        check(dry.returncode == 0, "dry run exits 0", dry.stderr.decode()[:200])
        check("would quarantine 1 file" in dry.stdout.decode(), "dry run prints the plan",
              dry.stdout.decode()[:200])
        check(os.path.isfile(shell), "CLI dry run left the file in place")

        applied = subprocess.run([sys.executable, SCRIPT] + common + ["--apply"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        check(applied.returncode == 0, "apply exits 0", applied.stderr.decode()[:200])
        check(not os.path.exists(shell), "CLI apply moved the file")

        restored = subprocess.run([sys.executable, SCRIPT, "--restore", shell,
                                   "--journal", journal],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        check(restored.returncode == 0, "restore exits 0", restored.stderr.decode()[:200])
        check(os.path.isfile(shell), "CLI restore put the file back")


def test_cli_requires_report_without_restore():
    """Argparse must refuse a quarantine run with no report rather than defaulting silently."""
    proc = subprocess.run([sys.executable, SCRIPT], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    check(proc.returncode != 0, "no arguments is an error")
    check("required" in proc.stderr.decode().lower() or "--report" in proc.stderr.decode(),
          "the error names the missing arguments", proc.stderr.decode()[:160])


def main():
    """Run every quarantine test group and exit non-zero if any check regressed."""
    for group in (test_dry_run_moves_nothing, test_apply_and_restore_round_trip,
                  test_changed_content_is_refused,
                  test_missing_and_already_held_are_reported_not_duplicated,
                  test_missing_source_file_is_reported, test_path_outside_docroot_is_refused,
                  test_review_verdicts_are_opt_in, test_corrupt_journal_is_refused,
                  test_multiple_files_keep_their_tree_shape,
                  test_holding_path_versions_an_existing_target,
                  test_cli_dry_run_and_apply, test_cli_requires_report_without_restore):
        group()
    print("test_webtree_quarantine.py: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


main()
