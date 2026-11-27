#!/usr/bin/env python3
"""Decide whether a dependency-bump pull request is a pure version change.

Why this exists: the review queue and the branch ruleset both require an `agent-review` check, so a
dependabot pull request can never merge - nobody reviews a one-line version bump, and nothing else can
post the check. Spending an adversarial agent session on `pyjwt: 2.10.1 -> 2.15.0` wastes tokens for
no judgement.

So the check is deterministic: read the diff, and accept it only if every changed line is a version
pin, the pins added are the pins removed, and the versions actually moved. What it accepts, and where:

  * `name==version` in a requirements file (`.txt`) - the name is read from both sides of the diff, so
    `+newdep==1.2.3` on its own is a dependency added, not bumped, and is refused. The line has to end
    with the version (a trailing `# comment` is allowed): `pyjwt==2.15.0 ; python_version < "0"` is
    the same version installed in no environment at all, so a marker is a change in *when* the
    dependency applies, and it is refused rather than read as a bump.
  * `name = { version = "=1.54.1", ... }` in a `.toml` - the inline-table form `gateway/Cargo.toml`
    uses for its dependencies (`tokio = { version = "=1.54.1", features = [...] }`), which a cargo bump
    edits in place and which the bare `version = "..."` shape cannot see, the name being on the line;
  * a bare `version = "1.2.3"` line in a `.toml` or `.lock` - the `[package]` / `[[package]]` form,
    where the name lives on another line, so this shape can only be checked for form;
  * a `checksum = "<hex>"` line in a `.lock` - bumping a package rewrites its checksum, and a diff that
    reads only the version line while the bytes changed too is a weaker proof than reading both;
  * `uses: owner/repo@<40 hex>` or `uses: owner/repo@v1.2.3` in a workflow (`.yml`/`.yaml`), with or
    without the `# vN` comment dependabot writes next to the SHA. `@main` is a branch, not a version.

Two shapes-and-files bugs the first version had, both found by review rather than by use: it applied
the `version = "..."` shape to *every* allowed extension, so `notes.txt` passed on a line that is a
version in name only - each shape is now scoped to the extensions that can contain it, which is what
the list above has always said; and it compared only *which* pins changed, never *what they changed
to*, so `-PyJWT==2.15.0` / `+PyJWT==2.15.0  # edited` was a clean bump - a file whose added versions
are the same set as its removed versions is now refused, because nothing moved.

Anything else - a new dependency, a changed URL, a `with:` value, a script edit riding along - is
refused. A refused bump stays open and is re-checked after the queue's failure backoff, which is where
a human reads it; nothing merges it.

Exit status is the contract the worker codes against, and the two failures must stay separable:
0 clean, 1 refused, 2 the check could not run (no key, API error, a file or a file list it could not
read). Only 0 and 1 are verdicts. Posting a 2 as a `fail` verdict records an outage on this host as a
review finding on someone's pull request, which is how the first version of this script behaved
(`sys.exit("...")` exits 1) - and an uncaught exception exits 1 as well, which is why everything past
the argument parse is caught rather than allowed to raise.

Usage: dependabot-check.py --pr 21
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

REPO = "17-of-12/fleet-filter"
API = "https://api.github.com"
EXIT_CLEAN, EXIT_REFUSED, EXIT_CANNOT_RUN = 0, 1, 2
PAGE_SIZE = 100
MAX_PAGES = 50  # 5000 files; past that the diff is reported as unreadable rather than partly read.

# Every shape a version pin takes, and the extensions that shape is legal in. `version = "..."` and
# `checksum = "..."` carry no name on the line (it sits on the line above), so they contribute an empty
# name rather than blocking the pairing rule - scoping them to .toml/.lock is what stops a `version =
# "1.0"` line in a text file from being read as a dependency bump.
PIN_PATTERNS = (
    ("requirement", (".txt",),
     re.compile(r"^[+-](?P<name>[A-Za-z0-9_.\-]+)==(?P<version>[0-9][A-Za-z0-9._+!]*)"
                r"(?:[ \t]*#[^\n]*)?$", re.I)),
    ("inline table", (".toml",),
     re.compile(r"""^[+-](?P<name>[A-Za-z0-9_.\-]+)\s*=\s*\{\s*version\s*=\s*["']"""
                r"""(?P<version>[^"'\s]+)["']""", re.I)),
    ("version key", (".toml", ".lock"),
     re.compile(r"""^[+-]\s*version\s*=\s*["'](?P<version>[^"'\s]+)["']""", re.I)),
    ("lock checksum", (".lock",),
     re.compile(r"""^[+-]checksum\s*=\s*["'](?P<version>[0-9a-fA-F]{40,})["']""", re.I)),
    ("action pin", (".yml", ".yaml"),
     re.compile(r"^[+-]\s*(?:-\s*)?uses:\s*(?P<name>[\w.\-/]+)@"
                r"(?P<version>[0-9a-f]{40}|v?\d[\w.\-]*)", re.I)),
)
ALLOWED_FILES = (".txt", ".toml", ".yml", ".yaml", ".lock")


def token():
    """Mint an installation token, exiting 2 - not 1 - when the mint itself fails.

    `sys.exit(message)` exits 1, which is the code a refusal answers with; the worker would then post a
    "machine-checked and refused" verdict for a pull request whose diff it never read.
    """
    out = subprocess.run([os.path.join(os.path.dirname(os.path.abspath(__file__)), "github-token.py")],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.stderr.write("dependabot-check: cannot mint a token: %s\n" % out.stderr.strip())
        raise SystemExit(EXIT_CANNOT_RUN)
    return out.stdout.strip()


def _get(path, value):
    """One GET, parsed as JSON, or exit 2 when the API did not answer or answered with something else."""
    request = urllib.request.Request(API + path, headers={
        "Authorization": "Bearer " + value, "Accept": "application/vnd.github+json",
        "User-Agent": "dependabot-check"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except (urllib.error.URLError, ValueError) as error:
        sys.stderr.write("dependabot-check: %s: %s\n" % (path, error))
        raise SystemExit(EXIT_CANNOT_RUN)


def _get_all_pages(path, value, limit=MAX_PAGES):
    """Every page of a list endpoint, or an exit when the endpoint holds more than `limit` pages.

    One call returns at most 100 entries, so a pull request touching 105 files used to be judged on the
    first hundred and the rest merged unread. Fetching `limit` pages and then returning the truncated
    list silently moved that same bug to `limit * 100` files: the answer to a diff that cannot be read
    is 2, the check could not run, not a verdict on the half that was visible.
    """
    found, page = [], 1
    while page <= limit:
        separator = "&" if "?" in path else "?"
        chunk = _get("%s%sper_page=%d&page=%d" % (path, separator, PAGE_SIZE, page), value)
        if not isinstance(chunk, list):
            sys.stderr.write("dependabot-check: %s did not return a list\n" % path)
            raise SystemExit(EXIT_CANNOT_RUN)
        found.extend(chunk)
        if len(chunk) < PAGE_SIZE:
            return found
        page += 1
    sys.stderr.write("dependabot-check: %s holds more than %d files, refusing to judge a diff it "
                     "cannot read\n" % (path, PAGE_SIZE * limit))
    raise SystemExit(EXIT_CANNOT_RUN)


def changed_files(pr, value):
    """The pull request's files as (filename, lines); `lines` is None when there was no patch to read."""
    files = []
    for item in _get_all_pages("/repos/%s/pulls/%d/files" % (REPO, pr), value):
        if not isinstance(item, dict) or "filename" not in item:
            # `item["filename"]` on a response that is not shaped like a file raised, and an uncaught
            # exception exits 1: a refusal posted for a diff that was never read.
            sys.stderr.write("dependabot-check: the files endpoint sent an entry with no filename\n")
            raise SystemExit(EXIT_CANNOT_RUN)
        patch = item.get("patch") or ""
        # A binary change, or a diff too large for the API to send, arrives without a `patch`. Zero
        # lines satisfies "every changed line is a version pin" without reading a single one, so the
        # absence is recorded and refused rather than won on an empty vote.
        files.append((item["filename"], None if (item.get("binary") or not patch.strip())
                      else patch.splitlines()))
    return files


def _is_header(line, name):
    """The patch's own header lines, and only those, so a content line that looks like one is read.

    The first version skipped anything starting with `---`, which also swallowed a *deleted* line whose
    content begins with `--` - the diff renders it `----`, and the deletion passed unread. The header
    names the file, so the filename is part of the match; `/dev/null` is the other side of a pure add
    or delete, and `diff --git` and `@@` lines carry no content either.
    """
    return (line.startswith(("diff ", "@@"))
            or line in ("--- a/%s" % name, "+++ b/%s" % name, "--- /dev/null", "+++ /dev/null"))


def pin_match(line, filename):
    """Classify one changed line as (shape, pinned name, pinned version), or (None, None, None).

    The file is part of the question: `version = "1.2.3"` is a dependency line in a `.toml` and prose
    in anything else, and the first version checked every shape against every allowed extension.
    """
    for shape, extensions, pattern in PIN_PATTERNS:
        if not filename.endswith(extensions):
            continue
        match = pattern.match(line)
        if match:
            groups = match.groupdict()
            return shape, groups.get("name") or "", groups.get("version") or ""
    return None, None, None


def verdict(files):
    """Whether every change is a version bump, and why not when it is not."""
    if not files:
        return False, "the pull request changes no files"
    for name, lines in files:
        if not name.endswith(ALLOWED_FILES):
            return False, "%s is not a dependency file" % name
        if lines is None:
            return False, ("%s: the API sent no patch to read (binary, or a diff too large to send), "
                           "so nothing here proves the change is only a version" % name)
        # `pyjwt`, `PyJWT` and `py_jwt` are one distribution (PEP 503), and `Actions/Checkout` is one
        # action, so both sides are compared on the same normalised key. The version is collected
        # alongside it because "the pin exists on both sides" is not the same claim as "the version
        # moved": an edited comment on an unchanged pin used to be read as a clean bump.
        pins = {"+": set(), "-": set()}
        versions = {"+": set(), "-": set()}
        for line in lines:
            if _is_header(line, name) or not line.startswith(("+", "-")):
                continue
            shape, pinned, version = pin_match(line, name)
            if shape is None:
                return False, "%s: not a version pin: %s" % (name, line.strip()[:90])
            side = "+" if line.startswith("+") else "-"
            if pinned:
                folded = pinned.lower().replace("_", "-") if shape == "requirement" else pinned.lower()
                pins[side].add((shape, folded))
            versions[side].add((shape, version))
        if pins["+"] != pins["-"]:
            return False, ("%s: changes which dependencies exist, not only their versions "
                           "(added %s, removed %s)"
                           % (name,
                              ", ".join(sorted(n for _, n in pins["+"])) or "none",
                              ", ".join(sorted(n for _, n in pins["-"])) or "none"))
        if versions["+"] == versions["-"]:
            return False, ("%s: the same %s on both sides of the diff, so no version moved (%s)"
                           % (name, "version" if versions["+"] else "content",
                              ", ".join(sorted((v for _, v in versions["+"]), key=str)) or "none"))
    return True, "every changed line in %s is a version pin" % ", ".join(n for n, _ in files)


def main(argv=None):
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Check that a dependency bump is only a bump")
    parser.add_argument("--pr", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        ok, why = verdict(changed_files(args.pr, token()))
    except SystemExit:
        raise  # exits that already chose their code: the mint, the API, the page ceiling
    except Exception as error:  # anything else could not run; exiting 1 would be posted as a refusal
        sys.stderr.write("dependabot-check: %s: %s\n" % (type(error).__name__, error))
        return EXIT_CANNOT_RUN
    print(("clean: " if ok else "refuse: ") + why)
    return EXIT_CLEAN if ok else EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
