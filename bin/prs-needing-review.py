#!/usr/bin/env python3
"""Print the oldest open pull request that still needs a verdict, and in which mode.

Why this exists: `bin/release-cve.sh` deliberately stops after opening the pull request, but the
review-and-merge step used to depend on the agent session that opened it having time left. When the
session hit its hour, the pull request sat open until a person merged it - which is not the design.

So the queue is the pull requests themselves. This prints the one to work on, or nothing:

  * open, in this repository (not a fork), authored by the release App or by dependabot
  * authored by the release App: named like release tooling output (branch `release/*` or a
    `signatures:` title), and reviewed by an agent session - mode `review`
  * authored by dependabot: on a `dependabot/*` branch, and decided by the deterministic pin check
    instead of a session - mode `machine`, because a version bump needs a rule, not a judgement
  * its `gate` check concluded success - there is no point reviewing a red tree
  * either it has no `agent-review` verdict yet, or it has a passing one and the merge did not happen
    (mode `merge`) - a pass whose merge failed at the session's death is otherwise stranded for ever,
    because nothing else looks at it

A failing verdict is re-workable, but not on every tick: any pull request whose last verdict failed
within `--backoff-minutes` is skipped, whether that verdict came from a session or from the machine
check. Skipping only the `review` mode was a bug - the queue stops at the lowest eligible number, so
one refused bump parked forever at the front of the queue also starved every pull request behind it.

Nothing here merges anything: merging needs a verdict, and a verdict comes from a reviewer or from the
deterministic check, never from this script.
"""

import argparse
import datetime
import json
import os
import subprocess
import sys
import urllib.request

REPO = "17-of-12/fleet-filter"
API = "https://api.github.com/repos/" + REPO


def token():
    """Mint a fresh installation token; a stale file is the failure this avoids."""
    out = subprocess.run([os.path.join(os.path.dirname(os.path.abspath(__file__)), "github-token.py")],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("prs-needing-review: cannot mint a token: " + out.stderr.strip())
    return out.stdout.strip()


def get(path, value):
    """GET a JSON endpoint with the installation token."""
    request = urllib.request.Request(API + path, headers={
        "Authorization": "Bearer " + value, "Accept": "application/vnd.github+json",
        "User-Agent": "fleet-filter"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def get_all_pages(path, value, limit=5):
    """Every page of a list endpoint, so an old pull request cannot hide behind the page size."""
    items, separator = [], "&" if "?" in path else "?"
    for page in range(1, limit + 1):
        chunk = get("%s%spage=%d" % (path, separator, page), value)
        if not chunk:
            break
        items.extend(chunk)
        if len(chunk) < 100:
            break
    return items


BOT = "pragma-17of12[bot]"
REPO = "17-of-12/fleet-filter"


DEPENDABOT = "dependabot[bot]"


def classify(pull, state):
    """Whether this pull request may enter the unattended review queue, and why not.

    The branch-name prefix is a label anyone can type, and a public repository accepts pull requests
    from forks. Since the review session runs with write tools and can mint an App token, a pull
    request from outside must never reach it - the gate passing is not provenance. So the rule is the
    two properties a fork cannot forge: the head repository is this one, and the author is the release
    App or dependabot. Anyone else, including a person with write access, is refused.
    """
    head = (pull.get("head") or {}).get("repo") or {}
    author = (pull.get("user") or {}).get("login")
    if head.get("full_name") != REPO:
        return False, "head is %s, not %s (fork or external branch)" % (
            head.get("full_name") or "an unknown repository", REPO)
    if author not in (BOT, DEPENDABOT):
        return False, "author is %s, not the release App" % author
    branch = (pull.get("head") or {}).get("ref") or ""
    title = pull.get("title") or ""
    if author == DEPENDABOT:
        # A version bump is a mechanical change: the gate and a pin-only diff decide it, not a review
        # session. Mode `machine` runs that check and posts the verdict without an agent.
        if not branch.startswith("dependabot/"):
            return False, "dependabot PR without a dependabot branch"
        gate = (state.get("gate") or (None, None))[0]
        if gate != "success":
            return False, "gate is %s" % (gate or "missing")
        if (state.get("agent-review") or (None, None))[0] == "success":
            return True, "merge"
        return True, "machine"
    if not (branch.startswith("release/") or title.startswith("signatures:")):
        return False, "not named like release tooling"
    gate = (state.get("gate") or (None, None))[0]
    if gate != "success":
        return False, "gate is %s" % (gate or "missing")
    verdict, finished = state.get("agent-review") or (None, None)
    if verdict == "success":
        return True, "merge"          # a pass with no merge: finish it, do not review again
    return True, "review"


def checks(sha, value):
    """The check runs on a commit, keyed by name, with when each finished."""
    payload = get("/commits/%s/check-runs" % sha, value)
    # Newest per name, by completion time rather than by position: the API's ordering is not something
    # this may depend on, and a stale PASS masking a newer FAIL is exactly the mistake it would cause.
    newest = {}
    for run in payload.get("check_runs", []):
        name = run.get("name")
        stamp = run.get("completed_at") or ""
        if name not in newest or stamp > (newest[name][1] or ""):
            newest[name] = (run.get("conclusion"), run.get("completed_at"))
    return newest


def recent_failure(verdict, backoff_minutes):
    """Whether the last verdict failed too recently to try again.

    A FAIL is re-workable, but the timer is ten minutes: without this, a review that keeps failing
    spends a full agent session every tick. The backoff is per pull request and stateless - the check
    run's own completion time is the record.
    """
    conclusion, finished = verdict or (None, None)
    if conclusion != "failure" or not finished:
        return False
    try:
        when = datetime.datetime.fromisoformat(finished.replace("Z", "+00:00"))
    except ValueError:
        return False
    age = (datetime.datetime.now(datetime.timezone.utc) - when).total_seconds()
    return age < backoff_minutes * 60


def main(argv=None):
    """CLI entry point: print a pull request number, and why, or nothing."""
    parser = argparse.ArgumentParser(description="Print the oldest release PR needing a verdict")
    parser.add_argument("--json", action="store_true", help="print what was examined, for debugging")
    parser.add_argument("--backoff-minutes", type=int, default=30,
                        help="do not re-review a pull request whose last verdict failed this recently")
    args = parser.parse_args(argv)

    value = token()
    pulls = get_all_pages("/pulls?state=open&per_page=100", value)
    examined = []
    for pull in sorted(pulls, key=lambda p: p["number"]):
        branch = pull["head"]["ref"]
        state = checks(pull["head"]["sha"], value)
        eligible, why = classify(pull, state)
        entry = {"number": pull["number"], "branch": branch,
                 "gate": (state.get("gate") or (None, None))[0],
                 "agent_review": (state.get("agent-review") or (None, None))[0],
                 "eligible": eligible, "why": why}
        examined.append(entry)
        if not eligible:
            continue
        # `merge` is exempt: there is nothing to redo there, only the merge to finish. Every mode that
        # would spend work again - a session or the machine check - honours the timer.
        if why != "merge" and recent_failure(state.get("agent-review"), args.backoff_minutes):
            entry["why"] = "separate"
            continue
        if args.json:
            print(json.dumps(entry))
        else:
            print("%d %s" % (pull["number"], why))
        return 0

    if args.json:
        print(json.dumps({"examined": examined, "needs_review": None}))
    return 1


if __name__ == "__main__":
    sys.exit(main())
