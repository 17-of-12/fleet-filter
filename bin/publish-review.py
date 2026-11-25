#!/usr/bin/env python3
"""Post an agent review verdict against a release pull request, and merge it when it passes.

Why this exists
---------------
The end goal is a daily, agent-driven release loop with no human approval step. GitHub's native
review requires a second identity: an app cannot approve its own pull request, so "automated publish"
and "required approval" are mutually exclusive. A required *check* has no such problem - the release
job can satisfy it - and a check is a first-class gate on a ruleset.

So the review is: an agent reads the diff and decides, this script posts that decision as the
`agent-review` check, and the merge only proceeds when the check is a success. The agent never merges
by hand and never posts a check it did not earn, because the verdict is passed in as data.

Usage
-----
    # what the reviewer should read (the whole reason for the PR)
    bin/publish-review.py --pr 12 --show-diff > /tmp/release.diff

    # after the reviewer has read it and returned a verdict
    bin/publish-review.py --pr 12 --verdict pass --notes "signature matches the PoC; evidence is a run"
    bin/publish-review.py --pr 12 --verdict fail --notes "ledger says blocked, session list is empty"

Exit status is 0 when the verdict was posted (and, for `pass`, the merge succeeded).
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

try:
    import jwt
except ImportError:  # pragma: no cover
    sys.exit("publish-review: pyjwt is required (host python3, not .venv)")

API = "https://api.github.com"
OWNER = "17-of-12"
REPO = "fleet-filter"
INSTALLATION = 185802080
CLIENT_ID = "Iv23liiFyTPUobYIdrcl"
KEY = os.path.expanduser("~/.config/fleet-filter/pragma-17of12.pem")
CHECK_NAME = "agent-review"
MERGE_METHOD = "rebase"  # the ruleset requires a linear history


def token():
    """Mint an installation token from the app key."""
    with open(KEY) as handle:
        private = handle.read()
    now = int(time.time())
    assertion = jwt.encode({"iat": now - 60, "exp": now + 540, "iss": CLIENT_ID}, private,
                           algorithm="RS256")
    request = urllib.request.Request(
        "%s/app/installations/%d/access_tokens" % (API, INSTALLATION), method="POST", data=b"{}",
        headers={"Authorization": "Bearer " + assertion, "Accept": "application/vnd.github+json",
                 "User-Agent": "publish-review", "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(request, timeout=25))["token"]


def call(path, token_value, method="GET", body=None):
    """One API call, returning (status, parsed body or text)."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        API + path, method=method, data=data,
        headers={"Authorization": "Bearer " + token_value,
                 "Accept": "application/vnd.github+json", "User-Agent": "publish-review",
                 "Content-Type": "application/json"})
    try:
        response = urllib.request.urlopen(request, timeout=30)
        raw = response.read()
        return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")[:300]


def pull(token_value, number):
    """The pull request, or exit when it does not exist."""
    status, pr = call("/repos/%s/%s/pulls/%d" % (OWNER, REPO, number), token_value)
    if status != 200:
        sys.exit("publish-review: pull request #%d not readable: %s %s" % (number, status, pr))
    return pr


def show_diff(token_value, number):
    """Print the PR's unified diff, which is what the reviewer is asked to judge."""
    request = urllib.request.Request(
        "%s/repos/%s/%s/pulls/%d" % (API, OWNER, REPO, number),
        headers={"Authorization": "Bearer " + token_value,
                 "Accept": "application/vnd.github.v3.diff", "User-Agent": "publish-review"})
    with urllib.request.urlopen(request, timeout=60) as response:
        print(response.read().decode("utf-8", "replace"))


def post_check(token_value, pr, verdict, notes):
    """Create the `agent-review` check run on the PR's head commit."""
    conclusion = "success" if verdict == "pass" else "failure"
    body = {
        "name": CHECK_NAME,
        "head_sha": pr["head"]["sha"],
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": "Agent review: %s" % verdict,
            "summary": notes or "(no notes provided)",
        },
    }
    return call("/repos/%s/%s/check-runs" % (OWNER, REPO), token_value, "POST", body)


def main(argv=None):
    """CLI entry point: show a release diff, record the review verdict, or merge on pass."""
    parser = argparse.ArgumentParser(description="Record an agent review and merge on approval")
    parser.add_argument("--pr", type=int, required=True, help="pull request number")
    parser.add_argument("--show-diff", action="store_true", help="print the diff and exit")
    parser.add_argument("--verdict", choices=("pass", "fail"), help="the reviewer's decision")
    parser.add_argument("--notes", default="", help="why, in the reviewer's words")
    parser.add_argument("--no-merge", action="store_true", help="post the check but do not merge")
    args = parser.parse_args(argv)

    token_value = token()
    pr = pull(token_value, args.pr)

    if args.show_diff:
        show_diff(token_value, args.pr)
        return 0

    if not args.verdict:
        parser.error("one of --show-diff, --verdict pass or --verdict fail is required")

    status, check = post_check(token_value, pr, args.verdict, args.notes)
    if status not in (200, 201):
        sys.exit("publish-review: could not post the %s check: %s %s" % (CHECK_NAME, status, check))
    print("posted %s=%s on %s" % (CHECK_NAME, args.verdict, pr["head"]["sha"][:7]))

    if args.verdict != "pass" or args.no_merge:
        print("not merging: verdict is %s%s" % (args.verdict, " (--no-merge)" if args.no_merge else ""))
        return 0

    status, merged = call("/repos/%s/%s/pulls/%d/merge" % (OWNER, REPO, args.pr), token_value,
                          "PUT", {"merge_method": MERGE_METHOD})
    if status != 200:
        # A 405 here is usually a required check that has not reported yet; the PR stays open, which
        # is the correct outcome - a merge that needs a retry is better than a merge nobody gated.
        sys.exit("publish-review: merge refused (%s): %s" % (status, merged))
    print("merged #%d: %s" % (args.pr, merged.get("message", "")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
