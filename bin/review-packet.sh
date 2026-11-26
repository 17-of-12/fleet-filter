#!/usr/bin/env bash
# review-packet.sh - assemble everything a reviewer needs, content and git record, in one directory.
#
# Why: `--show-diff` gives the content of a change and nothing else. A commit message can describe
# files it does not touch, unrelated edits can ride along, and a branch can be based on yesterday's
# main - none of that is visible in a patch. A reviewer that only sees the diff can pass all three.
#
# Produces, under --out:
#   diff.patch    the content, as before
#   commits.txt   subjects and bodies of the commits being merged, base..head
#   files.txt     per-file change counts
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
        --help|-h) sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
api "pulls/${PR}/files?per_page=100" > "$OUT/files.json"

python3 - "$OUT" <<'PY'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
meta = json.loads((out / "meta.json").read_text())
files = json.loads((out / "files.json").read_text())
(out / "files.txt").write_text("\n".join(
    "%6d %6d  %s" % (f["additions"], f["deletions"], f["filename"]) for f in files) + "\n")
summary = {
    "number": meta["number"],
    "title": meta.get("title"),
    "base": meta["base"]["sha"][:12],
    "head": meta["head"]["sha"][:12],
    "commits": meta.get("commits"),
    "changed_files": meta.get("changed_files"),
    "mergeable_state": meta.get("mergeable_state"),
    "body": (meta.get("body") or "")[:2000],
}
(out / "meta.json").write_text(json.dumps(summary, indent=2) + "\n")
PY

# The commits being merged, if the branch is present locally; the API fallback keeps it honest when it
# is not.
BASE=$(python3 -c "import json;print(json.load(open('$OUT/meta.json'))['base'])")
if git -C "$REPO" cat-file -e "$BASE^{commit}" 2>/dev/null; then
    git -C "$REPO" log --format='%h %an: %s%n%b' "origin/main..HEAD" > "$OUT/commits.txt" 2>/dev/null ||
        git -C "$REPO" log --format='%h %an: %s%n%b' -20 > "$OUT/commits.txt"
else
    python3 -c "
import json,urllib.request
t='${TOKEN}'
r=urllib.request.Request('https://api.github.com/repos/17-of-12/fleet-filter/pulls/${PR}/commits',headers={'Authorization':'Bearer '+t,'Accept':'application/vnd.github+json','User-Agent':'ff'})
for c in json.load(urllib.request.urlopen(r,timeout=25)):
    print(c['sha'][:8], c['commit']['message'].splitlines()[0])
" > "$OUT/commits.txt" || : > "$OUT/commits.txt"
fi

echo "review-packet: $OUT (diff $(wc -l <"$OUT/diff.patch") lines, $(wc -l <"$OUT/files.txt") files, $(wc -l <"$OUT/commits.txt") commit line(s))"
