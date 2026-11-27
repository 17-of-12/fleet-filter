#!/usr/bin/env python3
"""Audit this repository against the settings GitHub documents as security best practice.

Why a script rather than a checklist: a setting that was right in March is silently wrong in June, and
nobody re-reads settings pages. Every check here is one API field, so the answer is whether the repo has
it now, not whether someone once turned it on.

The eight checks, and what each is for:

  secret_scanning                 a token pushed by accident is found by GitHub, not by a reader
  secret_scanning_push_protection the push is refused instead of discovered afterwards
  dependabot_alerts               a dependency advisory becomes a finding on the repository
  dependabot_security_updates     ...and is fixed automatically, not when someone remembers
  private_vulnerability_reporting a researcher has a private channel rather than a public issue
  actions_default_read_token      a compromised workflow cannot write to the repo by default
  actions_sha_pinning             a tag that moves cannot change what CI runs
  ruleset_pr_required             main only moves through a reviewed pull request

Exit codes match bin/dependabot-check.py: 0 everything on, 1 something is missing, 2 the audit could not
answer. A failure to read must never be reported as a verdict, because the timer's output is read as one.

Usage:
    bin/github-audit.py            # report
    bin/github-audit.py --apply    # enable the ones that are safe to enable without a human
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

OWNER_REPO = "17-of-12/fleet-filter"
API = "https://api.github.com/repos/" + OWNER_REPO
ACTIONS_API = "https://api.github.com/repos/%s/actions/permissions" % OWNER_REPO
WORKFLOW_PERMS = ACTIONS_API + "/workflow"

EXIT_OK, EXIT_MISSING, EXIT_CANNOT_RUN = 0, 1, 2


def repo_bin():
    """The repository's bin/, whether this file runs from there or from /usr/local/sbin.

    The systemd unit runs the installed copy and sets FLEET_FILTER_REPO, while /usr/local/sbin holds
    fleet-filter-github-audit but never held github-token.py - so a minter path built from __file__
    alone made the installed audit die before its first API call. The env var is the documented location
    of the tree; falling back to this file's own directory keeps the source-tree invocation working.
    """
    repo = os.environ.get("FLEET_FILTER_REPO")
    if repo and os.path.isfile(os.path.join(repo, "bin", "github-token.py")):
        return os.path.join(repo, "bin")
    return os.path.dirname(os.path.abspath(__file__))


def token():
    """Mint an installation token, exiting 2 - not 1 - when the mint itself fails.

    `sys.exit(message)` exits 1, which is the code "settings are missing" answers with, so a broken
    credential would have been reported as an audit finding rather than as a run that never happened.
    """
    script = os.path.join(repo_bin(), "github-token.py")
    try:
        out = subprocess.run([script], capture_output=True, text=True)
    except OSError as error:
        sys.stderr.write("github-audit: cannot run the token minter %s: %s\n" % (script, error))
        sys.exit(EXIT_CANNOT_RUN)
    if out.returncode != 0:
        sys.stderr.write("github-audit: cannot mint a token: %s\n" % out.stderr.strip())
        sys.exit(EXIT_CANNOT_RUN)
    return out.stdout.strip()


def call(url, value, method="GET", body=None):
    """One API call, returning (status, parsed body)."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, method=method, data=data, headers={
        "Authorization": "Bearer " + value, "Accept": "application/vnd.github+json",
        "User-Agent": "github-audit", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")[:300]


def require(status, payload, what):
    """Pass an endpoint's payload through, or stop the run with 2.

    A non-200 makes call() hand back an error string, and `dict(...)` on it raises while a ruleset list
    degrades to [] - so a repository that has a ruleset gets reported as having none. Anything the audit
    needs to answer with has to answer; otherwise the run says "could not run" and exits 2.
    """
    if status != 200:
        sys.stderr.write("github-audit: cannot read %s (%s): %s\n" % (what, status, payload))
        sys.exit(EXIT_CANNOT_RUN)
    return payload


def audit(repo, actions, rulesets, pvr=None):
    """Which best-practice settings are on, as a list of (name, ok, detail)."""
    security = repo.get("security_and_analysis") or {}

    def feature(name):
        """The status string for one security_and_analysis feature."""
        return (security.get(name) or {}).get("status")

    # The list endpoint omits each ruleset's rules; the detail endpoint has them. A check that reads the
    # summary would report "no pull request rule" for a repo that has one.
    pr_rule = None
    for summary in rulesets if isinstance(rulesets, list) else []:
        detail = summary if summary.get("rules") else (summary.get("_detail") or {})
        if any(t.get("type") == "pull_request" for t in (detail.get("rules") or [])):
            pr_rule = detail
    # Its own endpoint, and it answers 404 when the setting is off, so anything that is not the
    # {"enabled": ...} object means off rather than crashing the whole audit.
    pvr_on = isinstance(pvr, dict) and pvr.get("enabled") is True
    return [
        ("secret_scanning", feature("secret_scanning") == "enabled", feature("secret_scanning")),
        ("secret_scanning_push_protection",
         feature("secret_scanning_push_protection") == "enabled",
         feature("secret_scanning_push_protection")),
        ("dependabot_alerts", feature("dependabot_security_updates") is not None,
         "alerts are on when the API exposes the feature block"),
        ("dependabot_security_updates",
         feature("dependabot_security_updates") == "enabled",
         feature("dependabot_security_updates")),
        ("private_vulnerability_reporting", pvr_on,
         "enabled" if pvr_on else "not enabled"),
        ("actions_default_read_token",
         (actions.get("default_workflow_permissions") == "read"),
         actions.get("default_workflow_permissions")),
        ("actions_sha_pinning", bool(actions.get("sha_pinning_required")), actions.get("sha_pinning_required")),
        ("ruleset_pr_required", pr_rule is not None,
         pr_rule.get("name") if pr_rule else "no ruleset requires a pull request"),
    ]


def main(argv=None):
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Audit repository security settings")
    parser.add_argument("--apply", action="store_true", help="enable what can be enabled without a human")
    args = parser.parse_args(argv)

    value = token()
    status, body = call(API, value)
    repo = require(status, body, "the repository")
    status, body = call(ACTIONS_API, value)
    actions = dict(require(status, body, "the actions permissions") or {})
    status, body = call(WORKFLOW_PERMS, value)
    actions.update(require(status, body, "the default workflow permissions") or {})
    status, body = call(API + "/rulesets", value)
    rulesets = require(status, body, "the rulesets")
    # Off is answered with 404 here, so this one endpoint is read without require(): see audit().
    pvr = call(API + "/private-vulnerability-reporting", value)[1]
    for summary in rulesets if isinstance(rulesets, list) else []:
        status, detail = call("%s/rulesets/%s" % (API, summary.get("id")), value)
        if status == 200:
            summary["_detail"] = detail

    results = audit(repo, actions, rulesets, pvr)
    width = max(len(name) for name, _, _ in results)
    missing = []
    for name, ok, detail in results:
        print("%-*s  %s  %s" % (width, name, "ok  " if ok else "MISSING", detail))
        if not ok:
            missing.append(name)

    if not args.apply:
        if missing:
            print("\n%d missing; --apply enables the safe ones" % len(missing))
        return EXIT_OK if not missing else EXIT_MISSING

    # Enabling secret scanning and push protection is safe: it cannot break a build, it can only refuse a
    # secret. The rest (ruleset changes) alter behaviour and need a decision, so they are reported, not
    # written.
    if "secret_scanning" in missing or "secret_scanning_push_protection" in missing:
        status, body = call(API, value, "PATCH", {"security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"}}})
        if status != 200:
            sys.stderr.write("github-audit: enabling secret scanning failed (%s): %s\n" % (status, body))
            return EXIT_CANNOT_RUN
        print("\nenabled secret scanning + push protection (%s)" % status)
    if "actions_default_read_token" in missing:
        status, body = call(WORKFLOW_PERMS, value, "PUT",
                            {"default_workflow_permissions": "read"})
        if status != 200:
            sys.stderr.write("github-audit: setting the workflow token failed (%s): %s\n" % (status, body))
            return EXIT_CANNOT_RUN
        print("set default workflow token to read-only (%s)" % status)
    return EXIT_OK if not missing else EXIT_MISSING


if __name__ == "__main__":
    code = 0
    try:
        code = main()
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 - a crash must not read as exit 1, the refusal code
        sys.stderr.write("github-audit: %s: %s\n" % (type(error).__name__, error))
        code = EXIT_CANNOT_RUN
    sys.exit(code)
