#!/usr/bin/env bash
# review-packet.sh - assemble everything a reviewer needs, content and git record, in one directory.
#
# Why: `--show-diff` gives the content of a change and nothing else. A commit message can describe
# files it does not touch, unrelated edits can ride along, and a branch can be based on yesterday's
# main - none of that is visible in a patch. A reviewer that only sees the diff can pass all three.
#
# Produces, under --out:
#   diff.patch    the content, as before
#   commits.txt   the pull request's commits with their bodies, plus the private commit the export
#                 was built from - what the merge actually brings in
#   files.txt     per-file change counts, every page of them
#   meta.json     base/head SHAs, ahead/behind counts, file count, mergeability
#
# Usage: review-packet.sh --pr 12 --out tmp/review-12

set -euo pipefail

REPO=${FLEET_FILTER_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
PR=""
OUT=""

die() { echo "review-packet: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --pr) PR=${2:?--pr needs a number}; shift 2 ;;
        --out) OUT=${2:?--out needs a directory}; shift 2 ;;
        --help|-h) sed -n '3,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$PR" ] || die "--pr is required"
[ -n "$OUT" ] || die "--out is required"
mkdir -p "$OUT"

python3 "$REPO/bin/publish-review.py" --pr "$PR" --show-diff > "$OUT/diff.patch" ||
    die "could not fetch the diff"
[ -s "$OUT/diff.patch" ] || die "the diff is empty"

TOKEN=$("$REPO/bin/github-token.py") || die "could not mint a GitHub token"
api() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/17-of-12/fleet-filter/$1"; }

api "pulls/${PR}" > "$OUT/meta.json"

python3 - "$OUT" "$TOKEN" <<'PY'
"""Write files.txt, commits.txt and the summary meta.json for one pull request.

Two defects this replaces, both of which quietly gutted the git record:

* `files?per_page=100` was a single call, and the API caps a page at 100 entries. PR 13 reports 105
  changed files and the packet listed 100, so the file a reviewer is looking for can be the one that
  is missing from the list they were handed. Every page is fetched now; files.json is the full list.
* commits.txt came from `git log origin/main..HEAD` in the private repository - and
  `bin/release-cve.sh` merges the branch into main *before* the release branch is cut, so that range
  is empty by the time a packet exists. PR 12 and PR 13 both shipped a 0-byte commits.txt, and "does
  each commit message match what it touches" cannot be answered from an empty file. The commits the
  pull request itself contains are the record of what a merge brings in, so they come from the API;
  the private commit behind the export is appended by the shell below, which is the only place that
  knows which commit was exported.
"""
import json
import sys
import urllib.request
from pathlib import Path

out, token = Path(sys.argv[1]), sys.argv[2]
meta = json.loads((out / "meta.json").read_text())


def get(path):
    """One API call, parsed."""
    request = urllib.request.Request(
        "https://api.github.com" + path,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json", "User-Agent": "review-packet"})
    return json.load(urllib.request.urlopen(request, timeout=30))


def get_all(path, per_page=100):
    """Every page of a collection endpoint; one call returns at most per_page entries."""
    found, page = [], 1
    while True:
        sep = "&" if "?" in path else "?"
        chunk = get("%s%sper_page=%d&page=%d" % (path, sep, per_page, page))
        found.extend(chunk)
        if len(chunk) < per_page:
            return found
        page += 1


files = get_all("/repos/17-of-12/fleet-filter/pulls/%d/files" % meta["number"])
commits = get_all("/repos/17-of-12/fleet-filter/pulls/%d/commits" % meta["number"])

(out / "files.json").write_text(json.dumps(files, indent=1) + "\n")
(out / "files.txt").write_text("\n".join(
    "%6d %6d  %s" % (f["additions"], f["deletions"], f["filename"]) for f in files) + "\n")
(out / "commits.json").write_text(json.dumps(
    [{"sha": c["sha"], "author": c["commit"]["author"]["name"],
      "message": c["commit"]["message"]} for c in commits], indent=1) + "\n")

lines = ["# commits in 17-of-12/fleet-filter#%d - what the merge brings in" % meta["number"]]
for commit in commits:
    subject = commit["commit"]["message"].splitlines()[0]
    lines.append("%s %s: %s" % (commit["sha"][:8], commit["commit"]["author"]["name"], subject))
    body = "\n".join(commit["commit"]["message"].splitlines()[1:]).strip()
    if body:
        lines.extend("  " + line if line else "" for line in body.splitlines())
(out / "commits.txt").write_text("\n".join(lines) + "\n")

summary = {
    "number": meta["number"],
    "title": meta.get("title"),
    "base": meta["base"]["sha"][:12],
    "head": meta["head"]["sha"][:12],
    "commits": meta.get("commits"),
    "changed_files": meta.get("changed_files"),
    "files_listed": len(files),
    "mergeable_state": meta.get("mergeable_state"),
    "body": (meta.get("body") or "")[:2000],
}
(out / "meta.json").write_text(json.dumps(summary, indent=2) + "\n")
PY

# The private commit(s) the export was built from, appended below the pull request's own commits.
# `origin/main..HEAD` is the right range only while the branch is ahead of main; once the release
# script has merged the branch (step 3, before the publish), HEAD *is* that commit, so name HEAD
# rather than writing an empty range and letting a reviewer read silence as "no commits".
append_private() {
    if [ -n "$(git -C "$REPO" rev-parse --verify --quiet origin/main 2>/dev/null)" ] &&
           [ "$(git -C "$REPO" rev-parse origin/main)" != "$(git -C "$REPO" rev-parse HEAD)" ]; then
        printf '# private commits ahead of origin/main in %s\n' "$REPO"
        git -C "$REPO" log --format='%h %an: %s%n%b' origin/main..HEAD
    else
        printf '# private commit bin/export-public.py archived into the release commit\n'
        printf '# (origin/main == HEAD: the branch was merged into main before the branch was cut)\n'
        git -C "$REPO" log --format='%h %an: %s%n%b' -1 HEAD
    fi
}

append_private >> "$OUT/commits.txt" 2>/dev/null || true

echo "review-packet: $OUT (diff $(wc -l <"$OUT/diff.patch") lines, $(wc -l <"$OUT/files.txt") files, $(wc -l <"$OUT/commits.txt") commit line(s))"
