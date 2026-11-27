#!/usr/bin/env python3
"""Re-cut a pull request whose base went stale, from its own commits.

Strict required checks compare the commit being merged, so once main moves, a pull request cannot be
merged: the rebase merge produces a commit neither check ran on. The escape is to rebase the branch onto
current main and open it again - which is mechanical, and which used to be a thing a person did by hand.

This does it from the pull request's own commits (`pull/N/head`), so it works the same for a release
branch and for a dependabot bump: nothing is reconstructed from the private tree, and the content that
was reviewed is the content that moves.

Usage: recut-pr.py --pr 23 [--dry-run]
Exit: 0 re-cut, 1 could not (conflict, missing branch), 2 nothing to do (base already current).
"""

import argparse
import json
import os
import subprocess
import sys

REPO = "https://github.com/17-of-12/fleet-filter.git"
OWNER_REPO = "17-of-12/fleet-filter"


def run(args, cwd=None, check=True):
    """Run a command, returning stdout; raise with its stderr when it fails and check is set."""
    done = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise RuntimeError("%s failed: %s" % (" ".join(args), done.stderr.strip()[:400]))
    return done.stdout.strip()


def api(path, method="GET", body=None):
    """One GitHub API call with the App token."""
    import urllib.request
    token = run([os.path.join(os.path.dirname(os.path.abspath(__file__)), "github-token.py")])
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        "https://api.github.com/repos/%s%s" % (OWNER_REPO, path), method=method, data=data,
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "User-Agent": "recut-pr", "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
        return json.loads(raw) if raw else None


def rebase_onto(clone, head_sha, branch):
    """Move the branch to head_sha and rebase it onto origin/main; return (ok, message).

    Split out so it can be tested against a throwaway repository: this is the part that decides whether
    a re-cut keeps the content, and a conflict here must stop rather than drop a change.
    """
    run(["git", "checkout", "--quiet", "-B", branch, head_sha], cwd=clone)
    done = subprocess.run(["git", "rebase", "origin/main"], cwd=clone, capture_output=True, text=True)
    if done.returncode != 0:
        run(["git", "rebase", "--abort"], cwd=clone, check=False)
        return False, done.stderr.strip()
    return True, ""


def main(argv=None):
    """CLI entry point: rebase the pull request onto main, push, replace it."""
    parser = argparse.ArgumentParser(description="Re-cut a pull request on current main")
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--clone", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                        "..", "tmp", "recut-clone"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    pull = api("/pulls/%d" % args.pr)
    base = (pull.get("base") or {}).get("sha")
    # The pull request's own head, taken from the API and used by name below. `git checkout FETCH_HEAD`
    # after `git fetch origin main pull/N/head` resolves to *main*: FETCH_HEAD records the fetched refs
    # in order and the first is main, so the re-cut branch was created at main and the pull request's
    # content was left behind - and pushing it as the head of a new pull request would have failed with
    # "no commits between main and release/recut-N".
    head_sha = (pull.get("head") or {}).get("sha")
    main_sha = (api("/git/refs/heads/main").get("object") or {}).get("sha")
    if base == main_sha:
        print("recut: base is current; nothing to do")
        return 2

    title = pull.get("title") or "release"
    clone = os.path.abspath(args.clone)
    if not os.path.isdir(os.path.join(clone, ".git")):
        run(["git", "clone", "--quiet", REPO, clone])
    run(["git", "fetch", "--quiet", "origin", "main", "pull/%d/head" % args.pr], cwd=clone)
    branch = "release/recut-%d" % args.pr

    if args.dry_run:
        print("recut: would rebase pull/%d/head onto main and push %s" % (args.pr, branch))
        return 0

    ok, message = rebase_onto(clone, head_sha, branch)
    if not ok:
        print("recut: the branch conflicts with main; a person has to resolve it:\n" + message[:500])
        return 1
    run(["git", "push", "--quiet", "origin", branch], cwd=clone)

    new = api("/pulls", "POST", {"title": title, "head": branch, "base": "main",
                                 "body": (pull.get("body") or "")
                                 + "\n\nRe-cut from #%d on current main: strict required checks compare"
                                   " the commit being merged." % args.pr})
    api("/issues/%d/comments" % args.pr, "POST",
        {"body": "Superseded by #%d, re-cut on current main. The base had moved, so a merge would have "
                 "landed a commit neither check ran on." % new["number"]})
    api("/pulls/%d" % args.pr, "PATCH", {"state": "closed"})
    print("recut: #%d closed, #%d open on %s" % (args.pr, new["number"], branch))
    return 0


if __name__ == "__main__":
    sys.exit(main())
