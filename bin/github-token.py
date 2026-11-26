#!/usr/bin/env python3
"""Print a fresh GitHub App installation token, valid for one hour.

Why a command rather than a file: installation tokens expire after 60 minutes, and a script that reads
a token from disk works exactly until it doesn't - the failure arrives as "Bad credentials" or a git
prompt for a username, hours after the file was written. Minting on demand costs one API call and
cannot go stale.

The App private key is the durable credential; the token is derived. Nothing is written to disk.

Usage
-----
    bin/github-token.py                    # print the token
    bin/github-token.py --export-env       # print TOKEN=<token> for eval
"""

import argparse
import json
import os
import sys
import time
import urllib.request

try:
    import jwt
except ImportError:  # pragma: no cover
    sys.exit("github-token: pyjwt is required (host python3, not .venv)")

INSTALLATION = 185802080
CLIENT_ID = "Iv23liiFyTPUobYIdrcl"
KEY = os.path.expanduser("~/.config/fleet-filter/pragma-17of12.pem")


def token():
    """Mint an installation token from the App key."""
    with open(KEY) as handle:
        private = handle.read()
    now = int(time.time())
    assertion = jwt.encode({"iat": now - 60, "exp": now + 540, "iss": CLIENT_ID}, private,
                           algorithm="RS256")
    request = urllib.request.Request(
        "https://api.github.com/app/installations/%d/access_tokens" % INSTALLATION, method="POST",
        data=b"{}",
        headers={"Authorization": "Bearer " + assertion, "Accept": "application/vnd.github+json",
                 "User-Agent": "fleet-filter", "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(request, timeout=25))["token"]


def main(argv=None):
    """CLI entry point: print a token, or a shell assignment for eval."""
    parser = argparse.ArgumentParser(description="Print a fresh installation token")
    parser.add_argument("--export-env", action="store_true", help="print TOKEN=<value> for eval")
    args = parser.parse_args(argv)
    value = token()
    print("TOKEN=%s" % value if args.export_env else value)
    return 0


if __name__ == "__main__":
    sys.exit(main())
