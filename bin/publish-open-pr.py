#!/usr/bin/env python3
"""Open the release pull request for a pushed branch, and print its number.

The release flows as: export -> commit on a branch -> push -> pull request -> agent review check ->
merge. This is the second step; `bin/publish-review.py` is the fourth.

Usage
-----
    bin/publish-open-pr.py --branch release/2026-11-26T041500Z --title "signatures: CVE-2026-XXXX"

Exit status is 0 when the pull request exists (created now, or already open for that branch).
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
    sys.exit("publish-open-pr: pyjwt is required (host python3, not .venv)")

API = "https://api.github.com"
OWNER = "17-of-12"
REPO = "fleet-filter"
INSTALLATION = 185802080
CLIENT_ID = "Iv23liiFyTPUobYIdrcl"
KEY = os.path.expanduser("~/.config/fleet-filter/pragma-17of12.pem")


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
                 "User-Agent": "publish-open-pr", "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(request, timeout=25))["token"]


def call(path, token_value, method="GET", body=None):
    """One API call, returning (status, parsed body or text)."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        API + path, method=method, data=data,
        headers={"Authorization": "Bearer " + token_value,
                 "Accept": "application/vnd.github+json", "User-Agent": "publish-open-pr",
                 "Content-Type": "application/json"})
    try:
        response = urllib.request.urlopen(request, timeout=30)
        raw = response.read()
        return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")[:300]


def main(argv=None):
    """CLI entry point: create or find the release pull request and print its number."""
    parser = argparse.ArgumentParser(description="Open the release pull request")
    parser.add_argument("--branch", required=True, help="the pushed release branch")
    parser.add_argument("--title", required=True, help="pull request title")
    parser.add_argument("--body", default="", help="pull request body")
    parser.add_argument("--base", default="main", help="base branch (default main)")
    args = parser.parse_args(argv)

    token_value = token()

    # Idempotent: a retried publish must not open a second PR for the same branch.
    status, existing = call("/repos/%s/%s/pulls?state=open&head=%s:%s"
                            % (OWNER, REPO, OWNER, args.branch), token_value)
    if status == 200 and existing:
        print(existing[0]["number"])
        return 0

    body = args.body or ("Release produced by bin/publish-public.sh from the private tree.\n\n"
                         "The diff is the export; `agent-review` is the review gate.")
    status, created = call("/repos/%s/%s/pulls" % (OWNER, REPO), token_value, "POST", {
        "title": args.title, "head": args.branch, "base": args.base, "body": body,
    })
    if status not in (200, 201):
        sys.exit("publish-open-pr: could not open the pull request: %s %s" % (status, created))
    print(created["number"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
