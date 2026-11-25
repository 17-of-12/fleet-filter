#!/usr/bin/env python3
"""Fail when a relative link in a tracked Markdown file does not resolve.

Documentation rots by link, not by prose: a file moves and every reference to it becomes a small lie
that nobody notices. This checks what a reader would click - relative paths and in-repo anchors - and
reports the file, the line and the target.

Absolute URLs are not fetched. Checking the internet on every gate run would make the gate flaky and
slow; a dead external link is a maintenance task, not a build failure.

Usage
-----
    bin/check-doc-links.py            # verify, print failures
    bin/check-doc-links.py --list     # print every link found, with its status
"""

import argparse
import os
import re
import pathlib
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Vendored trees are somebody else's documentation: their broken links are upstream's to fix, and
# failing our gate on them teaches the wrong lesson about what this check is for.
EXCLUDED_PREFIXES = ("vendor/",)

# [text](target) and [text](target "title"); images included because a broken image is a broken page.
LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


# Code comments and detector rules also name documents by path. Those references rotted silently when
# the docs were reorganised, because the markdown check never looked at them.
DOC_REFERENCE = re.compile(r"docs/[A-Za-z0-9_./-]+\.md")


def files_matching(patterns):
    """Files matching the patterns, from git when available and from the filesystem when not.

    The export tree has no `.git` in it, so a checker that only asks git finds nothing and reports
    success - the most dangerous kind of green. Falling back to a walk means the same check runs in a
    clone, a tarball and a working copy.
    """
    try:
        out = subprocess.run(["git", "-C", REPO_ROOT, "ls-files"] + list(patterns),
                             capture_output=True, text=True, check=True).stdout
        listed = [line for line in out.splitlines() if line.strip()]
        if listed:
            return listed
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    found = []
    for pattern in patterns:
        for path in pathlib.Path(REPO_ROOT).rglob(pattern):
            if path.is_file():
                found.append(str(path.relative_to(REPO_ROOT)))
    return sorted(set(found))


def tracked_code():
    """Files whose comments may name a document by path."""
    # Tests name documents that deliberately do not exist (fixtures for this very check).
    skip = EXCLUDED_PREFIXES + ("tests/",)
    return [line for line in files_matching(["*.rs", "*.py", "*.sh", "*.xml", "*.service", "*.timer"])
            if not line.startswith(skip)]


def tracked_markdown():
    """Every tracked .md file, so untracked drafts do not fail the gate."""
    return [line for line in files_matching(["*.md"])
            if not line.startswith(EXCLUDED_PREFIXES)]


def anchors(path):
    """Heading anchors a link can legitimately point at, in GitHub's slug form."""
    slugs = set()
    try:
        text = open(os.path.join(REPO_ROOT, path)).read()
    except OSError:
        return slugs
    for line in text.splitlines():
        if line.startswith("#"):
            title = line.lstrip("#").strip().lower()
            slug = re.sub(r"[^a-z0-9 \-]", "", title).replace(" ", "-")
            slugs.add(slug)
    return slugs


def check(link, source):
    """Return None when the link resolves, or a sentence saying why it does not."""
    if link.startswith(("http://", "https://", "mailto:", "#")):
        return None
    target, _, anchor = link.partition("#")
    base = os.path.dirname(source)
    path = os.path.normpath(os.path.join(base, target)) if target else source
    if not os.path.exists(os.path.join(REPO_ROOT, path)):
        return "missing file: %s" % path
    if anchor and path.endswith(".md") and anchor not in anchors(path):
        return "missing anchor: %s#%s" % (path, anchor)
    return None


def main(argv=None):
    """CLI entry point: verify every relative link and exit non-zero when one is broken."""
    parser = argparse.ArgumentParser(description="Verify relative links in tracked Markdown")
    parser.add_argument("--list", action="store_true", help="list every link and its status")
    args = parser.parse_args(argv)

    failures = []
    total = 0
    for source in tracked_markdown():
        try:
            text = open(os.path.join(REPO_ROOT, source)).read()
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for match in LINK.finditer(line):
                link = match.group(1)
                total += 1
                problem = check(link, source)
                if problem:
                    failures.append((source, lineno, link, problem))
                elif args.list:
                    print("ok      %-40s %s" % (source, link))

    for source in tracked_code():
        try:
            text = open(os.path.join(REPO_ROOT, source)).read()
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for path in DOC_REFERENCE.findall(line):
                total += 1
                if not os.path.exists(os.path.join(REPO_ROOT, path)):
                    failures.append((source, lineno, path, "named document does not exist"))
                elif args.list:
                    print("ok      %-40s %s" % (source, path))

    for source, lineno, link, problem in failures:
        print("BROKEN  %s:%d  %s  (%s)" % (source, lineno, link, problem))
    if total == 0:
        # A check that examined nothing must not look like a check that passed.
        print("check-doc-links: no links found - refusing to report success")
        return 1
    print("\n%d link(s) checked, %d broken" % (total, len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
