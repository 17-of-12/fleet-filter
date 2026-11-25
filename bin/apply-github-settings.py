#!/usr/bin/env python3
"""Apply this repository's GitHub settings, then read every one of them back.

Why a script and not a checklist: a settings page is a claim, and a read-back is evidence. The same
rule the project applies to exploit coverage applies here - after each change, fetch the value and
compare it with what was asked for, and fail loudly when they differ.

The GitHub App must hold `administration: write` **on the installation**. Adding the permission to
the app is not enough: the organisation has to approve the updated permissions for the installation,
or every call here returns "Resource not accessible by integration" (403). When that happens this
script says so instead of reporting a settings change that never happened.

Usage
-----
    bin/apply-github-settings.py                 # apply, then verify
    bin/apply-github-settings.py --verify-only   # just report current state
    bin/apply-github-settings.py --dry-run       # show what would be sent

Credentials come from the app private key and ids in gh.md's terms: the key path is
`~/.config/fleet-filter/pragma-17of12.pem`, the JWT `iss` is the app's client id, and the installation
id is fixed for this repository. Nothing is read from argv, so the key path never lands in ps.
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
except ImportError:  # pragma: no cover - the host interpreter has it; the venv does not
    sys.exit("apply-github-settings: pyjwt is required (host python3, not .venv)")

API = "https://api.github.com"
OWNER = "17-of-12"
REPO = "fleet-filter"
INSTALLATION = 185802080
CLIENT_ID = "Iv23liiFyTPUobYIdrcl"
KEY = os.path.expanduser("~/.config/fleet-filter/pragma-17of12.pem")

DESCRIPTION = "Virtual patching and bounded deception for web servers, with an evidence ledger"
TOPICS = ["security", "waf", "reverse-proxy", "rust", "http2", "incident-response",
          "virtual-patching"]

# The check name is the workflow job name; a status check that does not exist on a pull request can
# never pass, so the required context has to match it exactly.
PROTECTION = {
    "required_status_checks": {"strict": True, "contexts": ["gate"]},
    "enforce_admins": True,
    "required_pull_request_reviews": {
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": False,
        "required_approving_review_count": 1,
    },
    "restrictions": None,
    "required_linear_history": True,
    "allow_force_pushes": False,
    "allow_deletions": False,
    "required_conversation_resolution": True,
}


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
                 "User-Agent": "apply-settings", "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(request, timeout=25))["token"]


def call(path, method="GET", body=None, token_value=None, accept="application/vnd.github+json"):
    """One API call, returning (status, parsed body or text)."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        API + path, method=method, data=data,
        headers={"Authorization": "Bearer " + token_value, "Accept": accept,
                 "User-Agent": "apply-settings", "Content-Type": "application/json"})
    try:
        response = urllib.request.urlopen(request, timeout=30)
        raw = response.read()
        try:
            return response.status, json.loads(raw) if raw else None
        except ValueError:
            return response.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")[:300]


def apply_all(token_value, dry_run=False):
    """Send every setting; return the list of (name, status, detail) attempts."""
    attempts = []

    def send(name, path, method, body, accept="application/vnd.github+json"):
        if dry_run:
            attempts.append((name, "dry-run", json.dumps(body)[:90]))
            return
        status, out = call(path, method, body, token_value, accept)
        detail = out if isinstance(out, str) else "ok"
        attempts.append((name, status, detail))
        return out

    send("repository metadata", "/repos/%s/%s" % (OWNER, REPO), "PATCH",
         {"description": DESCRIPTION})
    send("topics", "/repos/%s/%s/topics" % (OWNER, REPO), "PUT", {"names": TOPICS},
         accept="application/vnd.github+json")
    send("branch protection", "/repos/%s/%s/branches/main/protection" % (OWNER, REPO), "PUT",
         PROTECTION)
    if not dry_run:
        # Code-security switches live in one object; send them together so a partial apply is visible.
        security = {"security_and_analysis": {
            "private_vulnerability_reporting": {"status": "enabled"},
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
        }}
        status, out = call("/repos/%s/%s" % (OWNER, REPO), "PATCH", security, token_value)
        attempts.append(("code security", status, out if isinstance(out, str) else "ok"))
        for name, path in (("dependabot alerts", "/repos/%s/%s/vulnerability-alerts" % (OWNER, REPO)),
                           ("automated security fixes",
                            "/repos/%s/%s/automated-security-fixes" % (OWNER, REPO))):
            status, out = call(path, "PUT", None, token_value)
            attempts.append((name, status, out if isinstance(out, str) else "ok"))
    return attempts


def verify(token_value):
    """Read back every setting; return (name, expected, actual, ok)."""
    results = []
    status, repo = call("/repos/%s/%s" % (OWNER, REPO), token_value=token_value)
    if status != 200:
        return [("repository state", "readable", "HTTP %s" % status, False)]
    results.append(("description", DESCRIPTION, repo.get("description"), repo.get("description") == DESCRIPTION))

    status, topics = call("/repos/%s/%s/topics" % (OWNER, REPO), token_value=token_value)
    actual_topics = topics.get("names") if isinstance(topics, dict) else topics
    results.append(("topics", ",".join(TOPICS), ",".join(actual_topics or []),
                    set(actual_topics or []) == set(TOPICS)))

    status, protection = call("/repos/%s/%s/branches/main/protection" % (OWNER, REPO),
                             token_value=token_value)
    if status != 200:
        results.append(("branch protection", "enabled", "HTTP %s" % status, False))
    else:
        reviews = protection.get("required_pull_request_reviews") or {}
        checks = protection.get("required_status_checks") or {}
        for name, expected, actual in (
            ("  require PR review", 1, reviews.get("required_approving_review_count")),
            ("  dismiss stale reviews", True, reviews.get("dismiss_stale_reviews")),
            ("  required checks", ["gate"], checks.get("contexts")),
            ("  strict (up to date)", True, checks.get("strict")),
            ("  linear history", True, (protection.get("required_linear_history") or {}).get("enforced")),
            ("  force pushes", False, (protection.get("allow_force_pushes") or {}).get("enabled")),
            ("  deletions", False, (protection.get("allow_deletions") or {}).get("enabled")),
            ("  enforce on admins", True, (protection.get("enforce_admins") or {}).get("enabled")),
            ("  conversation resolution", True,
             (protection.get("required_conversation_resolution") or {}).get("enabled")),
        ):
            results.append((name, expected, actual, actual == expected))

    security = repo.get("security_and_analysis") or {}
    for name, key in (("private vulnerability reporting", "private_vulnerability_reporting"),
                      ("secret scanning", "secret_scanning"),
                      ("push protection", "secret_scanning_push_protection")):
        value = (security.get(key) or {}).get("status")
        results.append((name, "enabled", value, value == "enabled"))

    status, _ = call("/repos/%s/%s/vulnerability-alerts" % (OWNER, REPO), token_value=token_value)
    results.append(("dependabot alerts", 204, status, status == 204))
    status, fixes = call("/repos/%s/%s/automated-security-fixes" % (OWNER, REPO),
                         token_value=token_value)
    enabled = fixes.get("enabled") if isinstance(fixes, dict) else False
    results.append(("automated security fixes", True, enabled, enabled is True))
    return results


def main(argv=None):
    """CLI entry point: apply the settings, then prove each one took effect."""
    parser = argparse.ArgumentParser(description="Apply and verify this repository's GitHub settings")
    parser.add_argument("--verify-only", action="store_true", help="report state without changing it")
    parser.add_argument("--dry-run", action="store_true", help="show the payloads, change nothing")
    args = parser.parse_args(argv)

    token_value = token()

    if not args.verify_only:
        attempts = apply_all(token_value, args.dry_run)
        if any(status == 403 for _, status, _ in attempts):
            print("403 from the API: the app holds `administration` but the installation does not.",
                  file=sys.stderr)
            print("Approve the updated permissions for installation %d:" % INSTALLATION, file=sys.stderr)
            print("  https://github.com/organizations/%s/settings/installations/%d" % (OWNER, INSTALLATION),
                  file=sys.stderr)
        print("%-28s %-8s %s" % ("setting", "status", "detail"))
        for name, status, detail in attempts:
            print("%-28s %-8s %s" % (name, status, detail if status != "ok" else ""))
        print()

    results = verify(token_value)
    width = max(len(name) for name, _, _, _ in results)
    failed = 0
    for name, expected, actual, ok in results:
        if not ok:
            failed += 1
        print("%-*s %-9s expected %-22s actual %s" % (width, name, "PASS" if ok else "FAIL",
                                                      json.dumps(expected), json.dumps(actual)))
    print("\n%d setting(s) verified, %d not in the expected state" % (len(results), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
