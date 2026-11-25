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

# Protection is a *ruleset* rather than the classic branch-protection rule, for one reason that
# matters operationally: a ruleset can name a bypass actor, and the release bot has to publish to
# main. Classic protection cannot exempt an app, and an app cannot approve its own pull request, so
# classic protection and automated publishing cannot both be true.
#
# The bypass is a deliberate, recorded exception: humans need a review, the release job does not,
# because what it publishes is an export of a tree that already passed the same gate.
RULESET_NAME = "main protection"
RULESET = {
    "name": RULESET_NAME,
    "target": "branch",
    "enforcement": "active",
    "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
    "bypass_actors": [{"actor_id": 5922290, "actor_type": "Integration", "bypass_mode": "always"}],
    "rules": [
        {"type": "pull_request", "parameters": {
            "required_approving_review_count": 1,
            "dismiss_stale_reviews_on_push": True,
            "require_code_owner_review": False,
            "require_last_push_approval": False,
            "required_review_thread_resolution": True,
        }},
        {"type": "required_status_checks", "parameters": {
            "strict_required_status_checks_policy": True,
            "required_status_checks": [{"context": "gate"}],
        }},
        {"type": "non_fast_forward"},
        {"type": "deletion"},
        {"type": "required_linear_history"},
    ],
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
        """Perform one setting change and record what the API said about it."""
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
    if not dry_run:
        # Removing the classic rule first: while it exists the stricter of the two applies, and its
        # lack of a bypass actor would keep rejecting the release job.
        status, out = call("/repos/%s/%s/branches/main/protection" % (OWNER, REPO), "DELETE",
                           None, token_value)
        attempts.append(("classic protection removed", status, out if isinstance(out, str) else "ok"))
        existing = None
        status, listed = call("/repos/%s/%s/rulesets" % (OWNER, REPO), token_value=token_value)
        if isinstance(listed, list):
            existing = next((r for r in listed if r.get("name") == RULESET_NAME), None)
        if existing:
            status, out = call("/repos/%s/%s/rulesets/%d" % (OWNER, REPO, existing["id"]), "PUT",
                               RULESET, token_value)
            attempts.append(("ruleset updated", status, out if isinstance(out, str) else "ok"))
        else:
            status, out = call("/repos/%s/%s/rulesets" % (OWNER, REPO), "POST", RULESET,
                               token_value)
            attempts.append(("ruleset created", status, out if isinstance(out, str) else "ok"))
    if not dry_run:
        # Code-security switches live in one object; send them together so a partial apply is visible.
        security = {"security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
        }}
        status, out = call("/repos/%s/%s" % (OWNER, REPO), "PATCH", security, token_value)
        attempts.append(("secret scanning", status, out if isinstance(out, str) else "ok"))
        # Private vulnerability reporting is not part of `security_and_analysis` on write: including
        # it there returns 200 and changes nothing, which is worse than an error. It has its own
        # endpoint, and its own GET to verify it.
        status, out = call("/repos/%s/%s/private-vulnerability-reporting" % (OWNER, REPO), "PUT",
                           {"enabled": True}, token_value)
        attempts.append(("private vulnerability reporting", status,
                         out if isinstance(out, str) else "ok"))
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

    status, listed = call("/repos/%s/%s/rulesets" % (OWNER, REPO), token_value=token_value)
    rule = next((r for r in listed if r.get("name") == RULESET_NAME), None) if isinstance(listed, list) else None
    if not rule:
        results.append(("branch ruleset", "present", "absent", False))
    else:
        status, detail = call("/repos/%s/%s/rulesets/%d" % (OWNER, REPO, rule["id"]),
                             token_value=token_value)
        types = {r["type"] for r in detail.get("rules", [])} if isinstance(detail, dict) else set()
        bypass = {b.get("actor_id") for b in (detail.get("bypass_actors") or [])} \
            if isinstance(detail, dict) else set()
        results.append(("ruleset enforced", "active", detail.get("enforcement"),
                        detail.get("enforcement") == "active"))
        results.append(("  require pull request", True, "pull_request" in types,
                        "pull_request" in types))
        results.append(("  required check gate", True,
                        any(r["type"] == "required_status_checks" and
                            any(c.get("context") == "gate"
                                for c in r.get("parameters", {}).get("required_status_checks", []))
                            for r in detail.get("rules", [])),
                        any(r["type"] == "required_status_checks" and
                            any(c.get("context") == "gate"
                                for c in r.get("parameters", {}).get("required_status_checks", []))
                            for r in detail.get("rules", []))))
        results.append(("  linear history", True, "required_linear_history" in types,
                        "required_linear_history" in types))
        results.append(("  no force push", True, "non_fast_forward" in types,
                        "non_fast_forward" in types))
        results.append(("  no deletion", True, "deletion" in types, "deletion" in types))
        results.append(("  release bot bypass", 5922290, sorted(bypass), 5922290 in bypass))

    security = repo.get("security_and_analysis") or {}
    for name, key in (("secret scanning", "secret_scanning"),
                      ("push protection", "secret_scanning_push_protection")):
        value = (security.get(key) or {}).get("status")
        results.append((name, "enabled", value, value == "enabled"))
    status, reporting = call("/repos/%s/%s/private-vulnerability-reporting" % (OWNER, REPO),
                             token_value=token_value)
    value = reporting.get("enabled") if isinstance(reporting, dict) else None
    results.append(("private vulnerability reporting", True, value, value is True))

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
