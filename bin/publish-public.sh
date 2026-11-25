#!/usr/bin/env bash
# publish-public.sh - publish the derived public tree as ordinary, incremental commits.
#
# Purpose
# -------
# The public repository is a *derived* artifact: `bin/export-public.py` rewrites estate identifiers,
# re-renders policies and drops what must not ship. The private history cannot be published, but that
# is not a reason for the public history to be absent.
#
# The earlier procedure rebuilt the repository from scratch on every publish - `git init`, one
# commit, `git push --force`. That destroyed the previous commit each time, so every file's date moved
# to the push time, `git log` showed a single entry, and nobody could see that a push had changed two
# files rather than a thousand. Described here because the symptom (all timestamps change) does not
# point at the cause (history rewritten), and the next person will hit it again otherwise.
#
# Design
# ------
# * A persistent local clone of the public repository keeps the history. Each publish syncs the fresh
#   export into that clone, commits the delta, and pushes a fast-forward. No force, ever: if the push
#   is rejected, this clone is behind and the right answer is to pull, not to overwrite.
# * A publish that changes nothing makes no commit, so the log stays a record of releases rather than
#   of timer firings.
# * The message is the caller's, so the log says why the release happened.
#
# Usage
# -----
#   bin/publish-public.sh --worktree ~/src/fleet-filter-public --message "Add CVE-2026-XXXX signature"
#   bin/publish-public.sh --worktree DIR --message MSG --token-file ~/.config/fleet-filter/token
#   bin/publish-public.sh --worktree DIR --message MSG --remote /tmp/test.git --no-token
#
# Exit status is 0 when the push succeeded or there was nothing to publish, 1 on any failure.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORKTREE=""
MESSAGE=""
REMOTE="https://github.com/17-of-12/fleet-filter.git"
TOKEN_FILE=""
EXPORT_DIR=""
DRY_RUN=0
VIA_PR=0
BRANCH=""

die() { echo "publish-public: $*" >&2; exit 1; }
note() { echo "publish-public: $*" >&2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --worktree) WORKTREE=${2:?--worktree needs a path}; shift 2 ;;
        --message) MESSAGE=${2:?--message needs text}; shift 2 ;;
        --remote) REMOTE=${2:?--remote needs a URL}; shift 2 ;;
        --token-file) TOKEN_FILE=${2:?--token-file needs a path}; shift 2 ;;
        --export-dir) EXPORT_DIR=${2:?--export-dir needs a path}; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --pr) VIA_PR=1; shift ;;
        --help|-h) sed -n '3,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$WORKTREE" ] || die "--worktree is required (a persistent clone of the public repository)"
[ -n "$MESSAGE" ] || die "--message is required: the log should say why this release happened"

if [ ! -d "$WORKTREE/.git" ]; then
    note "no clone at $WORKTREE; creating one from $REMOTE"
    git clone --quiet "$REMOTE" "$WORKTREE"
fi

# 1. Fresh export. Built every time, so the published tree cannot drift from the private one.
if [ -z "$EXPORT_DIR" ]; then
    EXPORT_DIR=$(mktemp -d)
    trap 'rm -rf "$EXPORT_DIR"' EXIT
    "${REPO_ROOT}/bin/export-public.py" --out "$EXPORT_DIR" --force >/dev/null ||
        die "the exporter refused this tree"
fi
[ -f "$EXPORT_DIR/README.md" ] || die "the export looks wrong: no README.md in $EXPORT_DIR"

# 2. Sync the export into the persistent clone. --delete because a file removed from the private tree
#    must disappear publicly; it is also the only way a stale file silently survives.
rsync -a --delete --exclude '.git' "$EXPORT_DIR"/ "$WORKTREE"/

cd "$WORKTREE"
if [ -z "$(git status --porcelain)" ]; then
    note "nothing to publish: the export matches the published tree"
    exit 0
fi

note "changes to publish:"
git status --porcelain | sed 's/^/  /' >&2

if [ "$DRY_RUN" -eq 1 ]; then
    note "--dry-run: not committing or pushing"
    exit 0
fi

# 3. One commit per release, authored as the App bot so the record matches who pushed it.
git add -A
git -c user.name="pragma-17of12[bot]" \
    -c user.email="5922290+pragma-17of12[bot]@users.noreply.github.com" \
    commit --quiet -m "$MESSAGE"
note "committed $(git log --format=%h -1): $(git log --format=%s -1)"

# 4a. Pull-request mode: the release travels as a PR so an agent review can gate it. The merge
#     itself is done by bin/publish-review.py after the reviewer has read the diff.
if [ "$VIA_PR" -eq 1 ]; then
    BRANCH="release/$(date -u +%Y-%m-%dT%H%M%SZ)"
    git checkout --quiet -b "$BRANCH"
    note "release branch: $BRANCH"
fi

# 4. Fast-forward only. The token goes in the environment, not argv, so it does not appear in ps.
if [ -n "$TOKEN_FILE" ]; then
    [ -r "$TOKEN_FILE" ] || die "cannot read token file: $TOKEN_FILE"
    TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE")
    if [ "$VIA_PR" -eq 1 ]; then
        GIT_CONFIG_COUNT=1 \
        GIT_CONFIG_KEY_0=http.extraheader \
        GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$TOKEN" | base64 -w0)" \
            git push --quiet origin "$BRANCH":"$BRANCH" || die "could not push the release branch"
        note "pushed branch $BRANCH; open the pull request next:"
        note "  bin/publish-open-pr.py --branch $BRANCH --title \"$(git log --format=%s -1)\""
        exit 0
    fi
    GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0=http.extraheader \
    GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$TOKEN" | base64 -w0)" \
        git push --quiet origin HEAD:main || die "push rejected: this clone is behind the remote (pull, do not force)"
else
    git push --quiet origin HEAD:main || die "push rejected: this clone is behind the remote (pull, do not force)"
fi
note "pushed $(git log --format=%h -1) to $REMOTE"
