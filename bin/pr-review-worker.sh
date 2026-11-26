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
session that opened it ran out of time. Work in ${REPO}. The skill section "Release review" is the
procedure; this is the budget that makes it fit.

BUDGET - the last session spent 56 minutes and 63 bash calls on a two-file diff. That was exploration,
not review. Hold to this:
  * verification is at most TEN tool calls. Past that you are exploring, not verifying - stop and act
    on what you measured.
  * read the files a finding names. Use bash only for a measurement read cannot make: a sha256 of the
    published file, one test file that is itself the finding. No git log, no git diff, no grep -r over
    the tree - commits.txt and files.txt in the packet already answer those.
  * do not run bin/check.sh --all; CI runs it. One test file you touched, nothing more.
  * a diff of three files or fewer with no source change is ONE pass. Do not give a version pin the
    procedure of a protocol change.

STAGE 0 - the packet, once.
  bin/review-packet.sh --pr ${PR} --out tmp/review-${PR}   (skip if it exists)
  meta.json is what the author claims; commits.txt is what the commits claim; files.txt is scope;
  diff.patch is the content. These four are the whole repository view you need.

STAGE 1 - reviewer subagent, adversarial, confined to the packet.
  Spawn qwen-reviewer with the packet directory and: assume the change is wrong and try to prove it,
  from these four files only - do not crawl the tree. Content first, then the git record, then style
  only where it obscures meaning. Ask for VERDICT plus NOTES.

STAGE 2 - verifier subagent, on the findings and nothing else.
  Spawn a SECOND subagent with the reviewer's findings verbatim. Per finding: CONFIRMED with file:line,
  or REFUTED with a measurement (sha256 of the file AS PUBLISHED on the head branch, a count in the
  evidence, a command's output). Nothing else. This is what stops a false finding costing a round - a
  reviewer here twice reported a hash mismatch by hashing the private tree.

STAGE 3 - act, on verified findings only.
  CONFIRMED: fix in ${REPO} on main, commit, re-publish the SAME branch:
    bin/publish-public.sh --worktree tmp/public-clone --pr --branch <head branch> \
        --token-file <file with a fresh token from bin/github-token.py> --message "<what changed>"
    bin/publish-open-pr.py --branch <branch> --title "<same title>"      # reuses the open PR
  REFUTED: do not "fix" it; record the measurement in the notes.
  Then, with all three voices:
    bin/publish-review.py --pr ${PR} --verdict <pass|fail> --notes "reviewer (adversarial): ... |
      verifier: confirmed <list> / refuted <list> + measurement | verified by primary: what I opened"
    bin/publish-review.py --pr ${PR} --merge-only     # on pass, once the gate reports success
  If that exits 3 the base is stale: bin/recut-pr.py --pr ${PR}. Do not retry the merge.

Never open a second pull request for the same work. A FAIL naming file and line is a better outcome
than a merge nobody checked.
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
