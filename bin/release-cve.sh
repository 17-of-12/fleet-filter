#!/usr/bin/env bash
# release-cve.sh - take a finished CVE worktree to a merged release without a human in the path.
#
# What it does, in order:
#   1. requires the worktree's checklist to be complete (`exploit-status --require-deploy`)
#   2. runs the gate in the worktree - nothing leaves without it
#   3. merges the cve/<CVE> branch into main (fast-forward only, so the branch must be current)
#   4. publishes through a pull request, then spawns the reviewer agent and merges on PASS
#
# What it refuses:
#   - a branch that is not based on current main (rebase first: the release must be reviewable)
#   - an incomplete checklist, a failing gate, or a dirty worktree
#
# The public repository is a derived export, so "deploy" here means: the fix is in the tree everyone
# else fetches. Policy distribution to hosts is their own pull, on their own timer.
#
# Usage:
#   release-cve.sh --cve CVE-2026-115560
#   release-cve.sh --cve CVE-2026-115560 --no-merge
#
# Exit status: 0 released and merged, 1 refused or failed, 2 the review did not pass.

set -euo pipefail

REPO=${FLEET_FILTER_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
CVE=""
OPEN_ONLY=0
TOKEN_FILE="${FLEET_FILTER_TOKEN_FILE:-$HOME/.config/fleet-filter/installation-token}"
WORKTREE=""
CLONE="${REPO}/tmp/public-clone"

die() { echo "release-cve: $*" >&2; exit 1; }
note() { echo "release-cve: $*" >&2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --cve) CVE=${2:?--cve needs an id}; shift 2 ;;
        --worktree) WORKTREE=${2:?--worktree needs a path}; shift 2 ;;
        --open-only) OPEN_ONLY=1; shift ;;
        --help|-h) sed -n '3,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$CVE" ] || die "--cve is required"
WORKTREE=${WORKTREE:-${REPO}/tmp/worktrees/${CVE}}
[ -d "$WORKTREE" ] || die "no worktree for ${CVE} at ${WORKTREE}"

# The rust half of the gate needs the toolchain ADR-0001 pins. On this host it is a rustup install in
# ~/.cargo/bin, which a login shell puts on PATH and a systemd-started worker session does not, so the
# gate printed `rust: cargo not on PATH` and the release died on a green tree. Add it when it exists;
# say nothing when it does not, because check.sh already reports a missing toolchain as a failure.
if [ -d "$HOME/.cargo/bin" ] && ! command -v cargo >/dev/null 2>&1; then
    PATH="$HOME/.cargo/bin:$PATH"
    export PATH
fi

# An installation token lives one hour, and publish-public.sh mints one on demand for exactly that
# reason - but this script always handed it a file, so the token written by the session that opened
# the first PR was reused five hours later and the branch push died with
# `fatal: could not read Username for 'https://github.com'`: git's fallback when the token in
# http.extraheader is refused. Refresh a token that is past its lifetime, and fail here rather than
# at the push. A personal access token (ghp_/github_pat_) has no lifetime, so it is left alone.
TOKEN_MAX_AGE=${FLEET_FILTER_TOKEN_MAX_AGE:-3300}
if [ -r "$TOKEN_FILE" ] && head -c 4 "$TOKEN_FILE" | grep -q '^ghs_' &&
        [ $(( $(date +%s) - $(stat -c %Y "$TOKEN_FILE") )) -gt "$TOKEN_MAX_AGE" ]; then
    note "${TOKEN_FILE} is older than ${TOKEN_MAX_AGE}s; minting a fresh installation token"
    "${REPO}/bin/github-token.py" >"${TOKEN_FILE}.new" || die "could not mint a GitHub token"
    chmod 600 "${TOKEN_FILE}.new" && mv "${TOKEN_FILE}.new" "$TOKEN_FILE"
fi

note "checklist: ${CVE}"
"$WORKTREE/.venv/bin/python" "$WORKTREE/bin/exploit-status.py" "$CVE" --require-deploy || \
    die "the checklist is incomplete; a release is not the step that fixes that"

note "gate in the worktree"
( cd "$WORKTREE" && VENV="$WORKTREE/.venv" PYTHONS="${PYTHONS:-$WORKTREE/.venv/bin/python}" \
    TIMEOUT=900 bin/check.sh --all ) || die "the gate failed in the worktree"

[ -z "$(git -C "$WORKTREE" status --porcelain)" ] || die "the worktree has uncommitted changes"
git -C "$WORKTREE" rev-parse --verify --quiet "cve/${CVE}" >/dev/null || die "expected branch cve/${CVE}"

note "merging cve/${CVE} into main (fast-forward only)"
git -C "$REPO" fetch -q origin
git -C "$REPO" merge --ff-only "cve/${CVE}" || die "not a fast-forward; rebase the branch on main first"
git -C "$REPO" push -q origin main || die "could not push main"

note "publishing through a pull request"
BRANCH=$(bin/publish-public.sh --worktree "$CLONE" --token-file "$TOKEN_FILE" --pr \
    --message "signatures: ${CVE}" 2>&1 | tee /dev/stderr |
    sed -n -e 's/^publish-public: release branch: \([^ ]*\).*/\1/p' \
           -e 's/^publish-public: pushed branch \([^ ]*\).*/\1/p' \
           -e 's/.*branch \([^;]*\);.*/\1/p' | tail -1)
[ -n "$BRANCH" ] || die "the publisher did not report a branch"

PR=$(bin/publish-open-pr.py --branch "$BRANCH" --title "signatures: ${CVE}" \
    --body "Automated release for ${CVE}; checklist and gate passed in the worktree.") || die "could not open the PR"
note "pull request #${PR}"

# The review is a qwen-reviewer subagent, dispatched by the session that called this script: a shell
# process cannot spawn a subagent, and re-implementing one with `pi --print` would silently be a
# different reviewer with a different prompt. So the contract is: this script opens the PR and prints
# the number; the session reviews it, posts the verdict with bin/publish-review.py, and merges.
note "PR=${PR}"
cat <<CONTRACT
The pull request is open. The session that dispatched this work now:

  1. bin/review-packet.sh --pr ${PR} --out tmp/review-${PR}
     -> diff.patch (the content), commits.txt (what the commits claim), files.txt (scope),
        meta.json (base/head, ahead/behind, mergeability)
  2. spawn a subagent of the read-only review class (qwen-reviewer) over that directory, and tell it
     to review ADVERSARIALLY - assume the change is wrong and try to prove it - on BOTH:
       content:  the counterexample, the request that slips past the new rule, the test that passes
                 for the wrong reason, the doc sentence the code does not support
     Priority order - spend the review where it pays:
       1. correctness and security of the content (the defect that ships)
       2. the git record: message vs what it touches, unrelated changes, branch currency
       3. style and naming, only where it obscures meaning - formatting is CI's job, not the
          reviewer's, and a reviewer that re-litigates rustfmt has no budget left for the defect
       git:      does every commit message match what that commit touches; does the PR carry changes
                 unrelated to its stated purpose; is the branch based on current main; is a file
                 changed that the description never mentions
  3. VERIFY the reviewer's claims yourself before anything goes out: open every file it names, confirm
     every line it cites, and check the commit claims against git. Neither agent's word is evidence.
  4. bin/publish-review.py --pr ${PR} --verdict <pass|fail> --notes "reviewer (adversarial, content+git):
     <notes> | verified by primary: <what you opened, what you found>"
  5. on pass, once the gate check reports: bin/publish-review.py --pr ${PR} --merge-only
CONTRACT
[ "$OPEN_ONLY" -eq 1 ] || note "waiting for the session to review; nothing else to do here"
exit 0
