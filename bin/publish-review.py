#!/usr/bin/env python3
"""Post an agent review verdict against a release pull request, and merge it when it passes.

Why this exists
---------------
The end goal is a daily, agent-driven release loop with no human approval step. GitHub's native
review requires a second identity: an app cannot approve its own pull request, so "automated publish"
and "required approval" are mutually exclusive. A required *check* has no such problem - the release
job can satisfy it - and a check is a first-class gate on a ruleset.

So the review is: an agent reads the diff and decides, this script posts that decision as the
`agent-review` check, and the merge only proceeds when the check is a success.

What this does *not* do is verify the verdict. The verdict arrives as a command-line argument, so the
script records a decision; it cannot prove a reviewer made it. The gate is only as honest as the
process that calls it - which is why the caller is the reviewer subagent, not a human typing `pass`,
and why the notes are posted verbatim where anyone can read them.

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
import re
import sys
import time
import urllib.error
import urllib.request


API = "https://api.github.com"
OWNER = "17-of-12"
REPO = "fleet-filter"
INSTALLATION = 185802080
CLIENT_ID = "Iv23liiFyTPUobYIdrcl"
KEY = os.path.expanduser("~/.config/fleet-filter/pragma-17of12.pem")
CHECK_NAME = "agent-review"
MERGE_METHOD = "rebase"  # the ruleset requires a linear history


def token():
    """Mint an installation token, importing jwt here rather than at module scope.

    The module-level import exited the process on import, which broke every interpreter that merely
    wanted to import this file - the gate runs the suite under two Pythons, and only one of them has
    the dependency.
    """
    try:
        import jwt
    except ImportError:  # pragma: no cover
        sys.exit("publish-review: pyjwt is required to mint a token (install requirements-dev.txt)")
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


def delete_release_branch(token_value, pr):
    """Delete the merged release branch, and only it.

    Both merge paths call this: the branch a release was reviewed on has no further use once main holds
    the commit, and leaving them behind made the branch list unreadable. Guarded by the `release/`
    prefix so a mistake here cannot delete main or a dependency-update branch, and best effort - a
    failure must not turn a successful merge into an error.
    """
    branch = (pr.get("head") or {}).get("ref") or ""
    if not branch.startswith("release/"):
        return
    status, _ = call("/repos/%s/%s/git/refs/heads/%s" % (OWNER, REPO, branch), token_value, "DELETE")
    print("deleted branch %s (%s)" % (branch, status))


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


ROLES = (
    ("reviewer:", re.compile(r"reviewer[^:]{0,40}:")),
    ("verifier:", re.compile(r"verifier[^:]{0,40}:")),
    ("verified by primary:", re.compile(r"verified by primary[^:]{0,40}:")),
)


def missing_roles(notes):
    """Which of the three role labels a pass verdict's notes fail to name.

    Prose cannot be proven, so it is required to exist: a session that skipped the verifier must now
    write the word and lie, rather than omit it and look compliant. That is a real reduction in what
    can go wrong quietly, and it is honest about being a forcing function rather than a proof.
    """
    text = notes or ""
    return [label for label, pattern in ROLES if not pattern.search(text)]


def machine_notes_ok(notes):
    """Whether --machine notes state what was checked where the message says to look for it.

    The flag exists so a reader can tell a deterministic verdict from an agent review, and a substring
    test let any note pass by mentioning the words anywhere ("looks fine, machine-checked: sort of").
    The requirement is a prefix, because that is what the error message promises.
    """
    return (notes or "").lstrip().startswith("machine-checked:")


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
    parser.add_argument("--machine", action="store_true",
                        help="a deterministic check produced this verdict, not an agent review")
    parser.add_argument("--no-merge", action="store_true", help="post the check but do not merge")
    parser.add_argument("--merge-only", action="store_true",
                        help="merge an already-posted pass, without posting another check")
    args = parser.parse_args(argv)

    token_value = token()
    pr = pull(token_value, args.pr)

    if args.show_diff:
        show_diff(token_value, args.pr)
        return 0

    if args.merge_only or args.verdict == "pass":
        # Strict required checks compare the commit being merged. If main moved since this pull request
        # was cut, a rebase merge produces a commit neither check ever saw, and GitHub answers 405 with
        # "required status checks are expected" - which reads like a pending check and is not. Refuse
        # here, with the reason, instead of retrying for ever.
        base = ((pr.get("base") or {}).get("sha") or "")[:12]
        status, main_ref = call("/repos/%s/%s/git/refs/heads/main" % (OWNER, REPO), token_value)
        head_sha = ((main_ref or {}).get("object") or {}).get("sha", "")[:12] if status == 200 else ""
        if base and head_sha and base != head_sha:
            print("publish-review: base is stale (pr %s, main %s); a rebase merge would land a commit "
                  "neither check ran on" % (base, head_sha))
            return 3

    if args.merge_only:
        # The check and the merge are separate on purpose: `gate` needs time to report, and a merge
        # that is retried after the checks land is better than one that fails and needs re-running.
        status, merged = call("/repos/%s/%s/pulls/%d/merge" % (OWNER, REPO, args.pr), token_value,
                              "PUT", {"merge_method": MERGE_METHOD})
        if status != 200:
            sys.exit("publish-review: merge refused (%s): %s" % (status, merged))
        print("merged #%d: %s" % (args.pr, merged.get("message", "")))
        delete_release_branch(token_value, pr)
        return 0

    if not args.verdict:
        parser.error("one of --show-diff, --verdict pass, --verdict fail or --merge-only is required")

    missing = [] if args.machine else missing_roles(args.notes)
    if args.machine and not machine_notes_ok(args.notes):
        sys.exit("publish-review: --machine requires notes that start with what was checked "
                 "(\"machine-checked: ...\"). Nothing was posted.")
    if args.verdict == "pass" and missing:
        sys.exit("publish-review: refusing to post a pass verdict that does not name the three roles "
                 "that produced it; missing: " + ", ".join(missing) + ". Nothing was posted.")

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
    delete_release_branch(token_value, pr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
