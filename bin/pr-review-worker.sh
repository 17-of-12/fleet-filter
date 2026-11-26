#!/usr/bin/env bash
# pr-review-worker.sh - finish what a timed-out session left: review an open release PR and merge it.
#
# The gap this closes: the agent session opens the pull request, then must review, verify and merge it
# with whatever time it has left. It usually has none, so pull requests sat open until a person
# merged them (#12, #13 and #15 did). The review is the part that must not be rushed, so it gets its
# own session, on its own timer, with a budget of its own - and the queue is simply "open PRs whose
# gate is green and which have no verdict".
#
# Usage: pr-review-worker.sh [--dry-run] [--timeout SECONDS]

set -euo pipefail

REPO=${FLEET_FILTER_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
# Ninety minutes: reviewer, verifier, fixes, a re-publish and a CI wait in one session. The
# ceiling is a backstop for a hang, not a budget for the work.
TIMEOUT="${PR_REVIEW_TIMEOUT:-5400}"
DRY_RUN=0
# Beside the checkout, not in /var/lib: this runs as the pi owner, and state it did not create it
# cannot write (the worker lock had exactly this bug).
LOCK="${FLEET_FILTER_PR_LOCK:-${REPO}/tmp/run/pr-review.lock}"

die() { echo "pr-review-worker: $*" >&2; exit 1; }
note() { echo "pr-review-worker: $*" >&2; }

merge_or_recut() {
    # Merge a pass that is already posted. Exit 3 from publish-review is not a refusal: it means the
    # base moved, so the pull request is re-cut from its own commits instead of being retried while
    # main walks away. Every merge path goes through here, so the machine mode cannot lose that rule
    # by copying the call and forgetting the branch - which is exactly what it used to do.
    local pr=$1 rc=0
    "${REPO}/bin/publish-review.py" --pr "$pr" --merge-only || rc=$?
    if [ "$rc" -eq 3 ]; then
        note "#${pr}: the base is stale; re-cutting from the pull request's own commits"
        "${REPO}/bin/recut-pr.py" --pr "$pr" || die "could not re-cut #${pr}"
        return 0
    fi
    [ "$rc" -eq 0 ] || die "merge refused for #${pr}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --timeout) TIMEOUT=${2:?--timeout needs seconds}; shift 2 ;;
        --help|-h) sed -n '3,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

mkdir -p "$(dirname "$LOCK")" || die "cannot create $(dirname "$LOCK")"
exec 9>"$LOCK" || die "cannot open ${LOCK}"
flock -n 9 || { note "a review session is already running"; exit 0; }

SELECTED=$("${REPO}/bin/prs-needing-review.py") || { note "no pull request needs attention"; exit 0; }
PR=${SELECTED%% *}
MODE=${SELECTED##* }
note "pull request #${PR}: ${MODE}"

if [ "$DRY_RUN" -eq 1 ]; then
    if [ "$MODE" = "machine" ]; then
        note "--dry-run: would run the deterministic dependency check for #${PR}, not a session"
    else
        note "--dry-run: would dispatch a review session for #${PR}"
    fi
    exit 0
fi

if [ "$MODE" = "machine" ]; then
    # A dependency bump: the diff decides, not a session. The check answers 0 clean, 1 refused and 2
    # "could not run", and only the first two are verdicts: posting a FAIL because a token could not be
    # minted files an outage on this host as a review finding on somebody's pull request.
    STATUS=0
    "${REPO}/bin/dependabot-check.py" --pr "$PR" >"${REPO}/tmp/dependabot-${PR}.txt" 2>&1 || STATUS=$?
    WHY=$(cat "${REPO}/tmp/dependabot-${PR}.txt")
    case "$STATUS" in
        0)
            # The pass is posted with --no-merge and merged by the same path the `merge` mode uses. A
            # verdict that merges inline and is then merged again always ends its run on "merge
            # refused", because the second merge has nothing left to merge.
            # The *post* answers 3 on a stale base too - publish-review checks the base before it
            # writes the check run - and `|| die` there left a clean bump with no verdict and no
            # backoff: the queue re-selects it every tick and dies again, so the one case the machine
            # check exists for, a dependabot bump while main moves, never reached the merge.
            rc=0
            "${REPO}/bin/publish-review.py" --pr "$PR" --verdict pass --machine --no-merge \
                --notes "machine-checked: ${WHY}. Deterministic check, no agent review: dependency bumps are reviewed by the gate and a pin-only diff." \
                || rc=$?
            if [ "$rc" -eq 3 ]; then
                note "#${PR}: the base is stale, so no verdict could be posted; re-cutting"
                "${REPO}/bin/recut-pr.py" --pr "$PR" || die "could not re-cut #${PR}"
            elif [ "$rc" -ne 0 ]; then
                die "could not post the machine verdict for #${PR}"
            else
                merge_or_recut "$PR"
            fi
            ;;
        1)
            "${REPO}/bin/publish-review.py" --pr "$PR" --verdict fail --machine \
                --notes "machine-checked: refused - ${WHY}. This needs a human or a review session, not a bump." \
                || die "could not post the refusal for #${PR}"
            ;;
        *)
            die "the dependency check could not run for #${PR} (exit ${STATUS}): $(head -n 1 "${REPO}/tmp/dependabot-${PR}.txt")"
            ;;
    esac
    exit 0
fi

if [ "$MODE" = "merge" ]; then
    # A pass was posted and the merge did not happen (the session died, or GitHub refused at that
    # moment). Finishing it needs no agent: the verdict exists, the gate is green.
    note "merging #${PR} on its posted pass"
    merge_or_recut "${PR}"
    exit 0
fi


"${REPO}/bin/pi-preflight.sh" >/dev/null || die "the agent runtime is not ready"
PI_HOME=${PI_HOME:-$HOME}
PI_BIN=${PI_BIN:-$(command -v pi || echo "${PI_HOME}/.local/bin/pi")}
SKILL=${CVE_WORKER_SKILL:-${REPO}/skills/exploit-signature-pipeline.md}

LOG_DIR="${FLEET_FILTER_LOG_DIR:-${REPO}/tmp/worker-logs}"
mkdir -p "$LOG_DIR"
LOG="${LOG_DIR}/pr-${PR}-$(date -u +%Y%m%dT%H%M%SZ).log"

PROMPT=$(cat <<PROMPT_END
Finish the release of pull request #${PR} in 17-of-12/fleet-filter. Nobody else will do it: the
session that opened it ran out of time, which is why it is open with a green gate and no verdict.
Work in ${REPO}. Read the skill section "Release review" and follow it exactly - three roles.

STAGE 0 - read the pull request itself, not only its diff.
  bin/review-packet.sh --pr ${PR} --out tmp/review-${PR}
  Read meta.json (the PR body says what the author claims), commits.txt, files.txt, diff.patch.

STAGE 1 - reviewer subagent, adversarial.
  Spawn a subagent of the read-only review class (qwen-reviewer) with the packet directory and an
  adversarial brief: assume the change is wrong and try to prove it. Content first (a counterexample,
  a request that slips past the new rule, a test that passes for the wrong reason, a doc sentence the
  code does not support), then the git record (does each commit message match what it touches, did
  unrelated changes ride along), then style only where it obscures meaning. Ask for VERDICT plus NOTES.

STAGE 2 - verifier subagent. This is the step that keeps a false finding from costing a round.
  Spawn a SECOND subagent, not the one above. Give it the reviewer's findings verbatim and this job:
  for each finding, prove it by quoting the file and line, or refute it by measuring - sha256 of the
  file AS PUBLISHED (raw.githubusercontent.com/17-of-12/fleet-filter/<head-branch>/path), a count in
  the recorded evidence, the actual command output. Answer per finding: CONFIRMED or REFUTED + evidence.
  A reviewer on this project twice reported a store-hash mismatch by hashing the private tree instead
  of the published one; the verifier is what catches that before it becomes a wasted round.

STAGE 3 - you act, and only on verified findings.
  CONFIRMED findings: fix them in ${REPO} on main, commit, then re-publish the SAME branch:
    bin/publish-public.sh --worktree tmp/public-clone --pr --branch <the PR head branch> \
        --token-file <a file holding a fresh token from bin/github-token.py> --message "<what changed>"
  then bin/publish-open-pr.py --branch <branch> --title "<same title>" (it reuses the open PR).
  REFUTED findings: do not "fix" them; say in the notes what the measurement showed.
  Then record all three voices and merge:
    bin/publish-review.py --pr ${PR} --verdict <pass|fail> --notes "reviewer (adversarial): ... |
      verifier: confirmed <list> / refuted <list> with the measurement | verified by primary: what I opened"
    bin/publish-review.py --pr ${PR} --merge-only      # on pass, once the gate reports success
     If that exits 3 the base has gone stale: run bin/recut-pr.py --pr ${PR}, which rebases the branch
     onto current main and opens the replacement. Do not retry the merge.

Never open a second pull request for the same work. If a defect is real and you cannot fix it inside
this session, post an honest FAIL naming the file and line - that is a better state than a merge
nobody checked.
PROMPT_END
)

note "log: ${LOG}"
set +e
( cd "$REPO" && timeout "$TIMEOUT" "$PI_BIN" --print --approve --skill "$SKILL" \
    --append-system-prompt "$PROMPT" "Begin. Review it and finish the release, or fail it honestly." ) \
    >"$LOG" 2>&1
STATUS=$?
set -e

# Whatever the session did, the queue answers for it: if the pull request is still open without a
# verdict, say so instead of reporting success.
if [ "$STATUS" -ne 0 ]; then
    note "review session exited ${STATUS}; pull request #${PR} may still be open"
    exit "$STATUS"
fi
STILL=$("${REPO}/bin/prs-needing-review.py" 2>/dev/null || true)
STILL_PR=${STILL%% *}
if [ "$STILL_PR" = "$PR" ]; then
    note "pull request #${PR} still has no verdict after the session"
    exit 1
fi
if [ -n "$STILL" ]; then
    note "pull request #${PR} is done; pull request #${STILL_PR} is next"
fi
note "pull request #${PR} has a verdict"
