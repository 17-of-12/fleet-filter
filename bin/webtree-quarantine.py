#!/usr/bin/env python3
"""Quarantine and restore files flagged by the Stage 4 webtree audit (Bundle Z7).

Why this exists
---------------
Z6 gave the console a finding list; Z7 is what makes the layer operable instead of merely loud.
The audit itself is deliberately read-only - it never moves a file - because a detector that also
mutates the docroot has to be right the first time. This script separates the two decisions: the
audit decides *what is suspicious*, and an operator decides *what gets moved*, with a recorded way
back.

The rules the design follows (Bundle Z7 as written in TODO.md):

  * **move, never delete.** The file goes to a holding directory and keeps its relative path, so
    `--restore` can put it back exactly where it came from.
  * **a quarantine is journaled before it happens.** The journal is the source of truth for what
    is currently held; a move that is not journaled would be an unrecoverable state change.
  * **content is verified on the way in and on the way back out.** The sha256 recorded at audit
    time is compared against the file being moved, so a file that changed between the audit and
    the action is refused rather than silently quarantined, and a restore proves it returned the
    bytes that were taken.
  * **only files the audit actually flagged are eligible.** An arbitrary path is not quarantined
    by this tool, which keeps "the tool moved my file" answerable from the report.

Stdlib-only and Python 3.6+ so it runs on any fleet host and inside the scanner image, matching
bin/webtree-audit.py.

Usage
-----
    bin/webtree-quarantine.py --report report.json --docroot /var/www/html --dry-run
    bin/webtree-quarantine.py --report report.json --docroot /var/www/html --apply
    bin/webtree-quarantine.py --restore /var/www/html/uploads/shell.php
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import time

DEFAULT_QUARANTINE_DIR = "/var/lib/fleet-filter/quarantine"
DEFAULT_JOURNAL = "/var/lib/fleet-filter/quarantine.json"
JOURNAL_VERSION = 1


def sha256_file(path):
    """Return the sha256 of a file's contents, or None if it cannot be read."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def load_journal(path):
    """Read the quarantine journal, or return an empty journal when the file does not exist.

    A journal that parses to something other than a dict is refused rather than overwritten: the
    journal is the only record of how to undo a quarantine, and silently replacing a corrupt one
    turns "we moved a file" into "we moved a file and lost its origin".
    """
    if not os.path.exists(path):
        return {"version": JOURNAL_VERSION, "entries": []}
    with open(path, "r", encoding="utf-8") as handle:
        journal = json.load(handle)
    if not isinstance(journal, dict) or "entries" not in journal:
        raise ValueError("%s is not a quarantine journal" % path)
    return journal


def save_journal(path, journal):
    """Write the journal atomically (temp file plus rename) so a crash cannot truncate it."""
    directory = os.path.dirname(path) or "."
    if not os.path.isdir(directory):
        os.makedirs(directory)
    temp = "%s.tmp" % path
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(journal, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temp, path)


def flagged_files(report, verdicts=("quarantine",)):
    """Return `{path: record}` for report entries whose verdict is in `verdicts`.

    The report's own `files[].path` is the absolute path the audit produced, so eligibility comes
    from the report rather than from a path someone typed at a prompt.
    """
    found = {}
    for entry in (report.get("files") or []):
        path = entry.get("path")
        if not path:
            continue
        if entry.get("verdict") in verdicts:
            found[os.path.normpath(path)] = entry
    return found


def holding_path(docroot, quarantine_dir, path, stamp=None):
    """Return the path a docroot file should be moved to, keeping its position under the root.

    A file outside the docroot is refused here rather than flattened into the holding directory,
    because a restore has to be able to reconstruct where it came from from the holding path alone.
    """
    docroot = os.path.normpath(docroot)
    normalized = os.path.normpath(path)
    if normalized == docroot or not normalized.startswith(docroot + os.sep):
        raise ValueError("%s is not inside docroot %s" % (path, docroot))
    relative = os.path.relpath(normalized, docroot)
    target = os.path.join(os.path.normpath(quarantine_dir), relative)
    if os.path.exists(target):
        target = "%s.%s" % (target, stamp or str(int(time.time())))
    return target


def quarantine(report_path, docroot, quarantine_dir=DEFAULT_QUARANTINE_DIR,
               journal_path=DEFAULT_JOURNAL, apply_changes=False, verdicts=("quarantine",)):
    """Quarantine every file the report flagged, returning a per-file result list.

    With `apply_changes` false this reports what would move and changes nothing, which is how the
    operator sees the blast radius before the first file leaves a live docroot.
    """
    with open(report_path, "r", encoding="utf-8") as handle:
        report = json.load(handle)
    targets = flagged_files(report, verdicts=verdicts)
    journal = load_journal(journal_path)
    active = {os.path.normpath(e["source"]) for e in journal.get("entries", [])
              if e.get("action") == "quarantined"}
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    results = []

    for path, record in sorted(targets.items()):
        result = {"path": path, "verdict": record.get("verdict"),
                  "score": record.get("score"), "action": None, "detail": None}
        if path in active:
            result.update(action="skipped", detail="already quarantined")
            results.append(result)
            continue
        if not os.path.isfile(path):
            result.update(action="missing", detail="flagged file is not present")
            results.append(result)
            continue
        actual = sha256_file(path)
        expected = record.get("sha256")
        if expected and actual != expected:
            result.update(action="refused",
                          detail="content changed since the audit (sha256 %s != %s)"
                                 % (actual, expected))
            results.append(result)
            continue
        try:
            target = holding_path(docroot, quarantine_dir, path, stamp=stamp)
        except ValueError as exc:
            result.update(action="refused", detail=str(exc))
            results.append(result)
            continue
        if not apply_changes:
            result.update(action="would-quarantine", detail=target)
            results.append(result)
            continue
        try:
            parent = os.path.dirname(target)
            if not os.path.isdir(parent):
                os.makedirs(parent)
            shutil.move(path, target)
        except OSError as exc:
            result.update(action="failed", detail=str(exc))
            results.append(result)
            continue
        journal["entries"].append({
            "action": "quarantined", "source": path, "held_at": target,
            "sha256": actual, "at": stamp, "verdict": record.get("verdict"),
            "score": record.get("score"), "report": os.path.abspath(report_path),
        })
        save_journal(journal_path, journal)
        result.update(action="quarantined", detail=target)
        results.append(result)
    return results


def restore(source_path, journal_path=DEFAULT_JOURNAL, docroot=None):
    """Restore one quarantined file to its recorded origin, verifying the content on the way back.

    Returns the restored path. Raises when the file is not held, is already back at its origin, or
    does not hash to what was recorded - a partial or tampered holding copy must not be restored
    silently.
    """
    journal = load_journal(journal_path)
    normalized = os.path.normpath(source_path)
    entry = None
    for candidate in reversed(journal.get("entries", [])):
        if candidate.get("action") == "quarantined" and \
                os.path.normpath(candidate.get("source", "")) == normalized:
            entry = candidate
            break
    if entry is None:
        raise ValueError("%s is not recorded as quarantined in %s" % (source_path, journal_path))
    held = entry.get("held_at")
    if not held or not os.path.isfile(held):
        raise ValueError("held copy %s is missing; refusing to mark it restored" % held)
    if os.path.exists(normalized):
        raise ValueError("origin %s already exists; refusing to overwrite" % normalized)
    actual = sha256_file(held)
    if actual != entry.get("sha256"):
        raise ValueError("held copy hashes to %s, journal records %s"
                         % (actual, entry.get("sha256")))
    if docroot:
        docroot_norm = os.path.normpath(docroot)
        if not normalized.startswith(docroot_norm + os.sep):
            raise ValueError("origin %s is not inside docroot %s"
                             % (normalized, docroot_norm))
    directory = os.path.dirname(normalized)
    if not os.path.isdir(directory) and not apply_dir(directory):
        raise ValueError("cannot recreate %s" % directory)
    shutil.move(held, normalized)
    restored = sha256_file(normalized)
    if restored != entry.get("sha256"):
        raise ValueError("restored file hashes to %s, expected %s"
                         % (restored, entry.get("sha256")))
    journal["entries"].append({"action": "restored", "source": normalized,
                               "sha256": restored, "at": time.strftime(
                                   "%Y%m%dT%H%M%SZ", time.gmtime()),
                               "restored_from": held})
    save_journal(journal_path, journal)
    return normalized


def apply_dir(directory):
    """Create `directory` if possible; return False when it cannot be created."""
    try:
        os.makedirs(directory)
        return True
    except OSError:
        return False


def main(argv=None):
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Quarantine or restore audited webtree files")
    parser.add_argument("--report", help="webtree audit report to act on")
    parser.add_argument("--docroot", help="docroot the report was produced for")
    parser.add_argument("--quarantine-dir", default=DEFAULT_QUARANTINE_DIR,
                        help="holding directory (default %s)" % DEFAULT_QUARANTINE_DIR)
    parser.add_argument("--journal", default=DEFAULT_JOURNAL,
                        help="quarantine journal (default %s)" % DEFAULT_JOURNAL)
    parser.add_argument("--apply", action="store_true",
                        help="move the files (default is a dry run)")
    parser.add_argument("--include-review", action="store_true",
                        help="also treat `review` verdicts as eligible")
    parser.add_argument("--restore", metavar="PATH",
                        help="restore this original path from the journal instead of quarantining")
    args = parser.parse_args(argv)

    if args.restore:
        restored = restore(args.restore, journal_path=args.journal)
        print("restored %s" % restored)
        return 0
    if not args.report or not args.docroot:
        parser.error("--report and --docroot are required unless --restore is used")

    verdicts = ("quarantine", "review") if args.include_review else ("quarantine",)
    results = quarantine(args.report, args.docroot, quarantine_dir=args.quarantine_dir,
                         journal_path=args.journal, apply_changes=args.apply,
                         verdicts=verdicts)
    verb = "quarantined" if args.apply else "would quarantine"
    for result in results:
        print("%-16s %s (%s)" % (result.get("action"), result.get("path"),
                                 result.get("detail") or ""))
    moved = sum(1 for r in results if r.get("action") in
                ("quarantined" if args.apply else "would-quarantine"))
    print("%s %d file(s); %d refused, %d missing, %d already held" % (
        verb, moved,
        sum(1 for r in results if r.get("action") == "refused"),
        sum(1 for r in results if r.get("action") == "missing"),
        sum(1 for r in results if r.get("action") == "skipped")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
