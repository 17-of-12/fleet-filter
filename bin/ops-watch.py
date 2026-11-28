#!/usr/bin/env python3
"""Watch the release loop while nobody is looking, and record what it saw.

Why this is a timer and not a `sleep 21600` in an agent session: the session ends, the timer does not.
A watch that only exists while a person is watching is not a watch.

What it checks, per run:

  timers        every unit the loop depends on is active
  queue         work items waiting, and items parked in blocked/ (a park is the loop admitting it
                could not finish something)
  pull requests open PRs, how long each has had no verdict, and whether its gate went red
  drift         private tree vs published tree (an unpushed commit means a release is owed)
  disk          the run directories and logs are not filling the disk

It repairs the one thing that is safe to repair unattended - an inactive unit it manages - and writes
everything else to a log for a person to read. A watcher that "fixes" what it does not understand is
how a quiet failure becomes a loud one.

Usage:
    ops-watch.py                 # check, print, append to the log
    ops-watch.py --no-log        # check and print only
"""

import argparse
import calendar
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

# Installed copies live in /usr/local/sbin, where `dirname/..` is /usr/local and every path derived from
# it is wrong - the same mistake that broke the CVE worker. The unit sets FLEET_FILTER_REPO; the fallback
# is for running it from a checkout.
REPO = os.environ.get("FLEET_FILTER_REPO") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.exists(os.path.join(REPO, "bin", "github-token.py")):
    sys.exit("ops-watch: no bin/github-token.py under %s; set FLEET_FILTER_REPO" % REPO)
LOG = os.environ.get("FLEET_FILTER_WATCH_LOG", "/var/lib/fleet-filter/ops-watch.log")
UNITS = ("fleet-filter-cve-triage.timer", "fleet-filter-cve-worker.timer",
         "fleet-filter-pr-review.timer", "fleet-filter-policy-publish.timer",
         # install-runtime.sh installs this one too; a watch that checks four of the six timers it
         # ships cannot report "timers: every unit the loop depends on is active".
         "fleet-filter-github-audit.timer")
QUEUE = "/var/lib/fleet-filter/workqueue"
# A pull request with a green gate and no verdict for longer than this means the review loop is behind
# or stuck; the session budget is 90 minutes, so two hours is "something is wrong".
WEDGED_MINUTES = 120


def api(path):
    """One GitHub API call with a freshly minted token."""
    out = subprocess.run([os.path.join(REPO, "bin", "github-token.py")], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("cannot mint a token: " + out.stderr.strip())
    request = urllib.request.Request(
        "https://api.github.com/repos/17-of-12/fleet-filter" + path,
        headers={"Authorization": "Bearer " + out.stdout.strip(),
                 "Accept": "application/vnd.github+json", "User-Agent": "ops-watch"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def systemctl(*args):
    """Run systemctl and return its output."""
    return subprocess.run(["systemctl"] + list(args), capture_output=True, text=True).stdout.strip()


def check_timers():
    """Which managed timers are not active, and start them once.

    `is-active` cannot tell a unit someone stopped on purpose from one that died, which is why the
    list is closed to the units this project owns and why the only repair attempted is a start.
    """
    findings, repaired = [], []
    for unit in UNITS:
        if systemctl("is-active", unit) == "active":
            continue
        findings.append("%s is not active" % unit)
        if subprocess.run(["sudo", "-n", "systemctl", "start", unit],
                          capture_output=True).returncode == 0:
            repaired.append(unit)
    return findings, repaired


def check_queue():
    """Work waiting, and work the loop parked."""
    waiting = [f for f in os.listdir(QUEUE) if f.endswith(".json")] if os.path.isdir(QUEUE) else []
    blocked_dir = os.path.join(QUEUE, "blocked")
    blocked = [f for f in os.listdir(blocked_dir) if f.endswith(".json")] if os.path.isdir(blocked_dir) else []
    return waiting, blocked


def check_pulls():
    """Open pull requests, and the ones that have waited too long without a verdict."""
    stale = []
    for pull in api("/pulls?state=open&per_page=50"):
        # calendar.timegm, not time.mktime: the API answers in UTC and mktime would read the stamp as
        # local time, so the age of a PR would carry the host's UTC offset.
        opened = calendar.timegm(time.strptime(pull["created_at"], "%Y-%m-%dT%H:%M:%SZ"))
        # The wedge threshold is measured from the last activity, not from opening: a pull request
        # that was reviewed five minutes ago is not waiting on an agent for a week. `open` in the
        # message is still the age since it was opened, which is the number the report quotes.
        last = calendar.timegm(time.strptime(
            pull.get("updated_at") or pull["created_at"], "%Y-%m-%dT%H:%M:%SZ"))
        age_hours = (time.time() - opened) / 3600
        idle_hours = (time.time() - last) / 3600
        checks = api("/commits/%s/check-runs?per_page=100"
                     % pull["head"]["sha"]).get("check_runs", [])
        verdict = next((c for c in checks if c["name"] == "agent-review"), None)
        gate = next((c for c in checks if c["name"] == "gate"), None)
        if gate and gate.get("conclusion") == "failure":
            stale.append("#%d gate is red" % pull["number"])
        elif verdict is None and idle_hours * 60 > WEDGED_MINUTES:
            stale.append("#%d open %.1fh, nothing on it for %.1fh, no verdict"
                         % (pull["number"], age_hours, idle_hours))
    return stale


def check_drift():
    """Commits in the private tree that the published tree does not have."""
    out = subprocess.run(["git", "-C", REPO, "rev-list", "--count", "origin/main..HEAD"],
                         capture_output=True, text=True)
    count = int(out.stdout.strip() or 0) if out.returncode == 0 else 0
    return count


def check_disk():
    """Free space where the run directories and logs live."""
    usage = shutil.disk_usage("/var/lib/fleet-filter" if os.path.isdir("/var/lib/fleet-filter") else REPO)
    return usage.free / (1024 ** 3)


def main(argv=None):
    """Check everything, print a paragraph, append it to the log."""
    parser = argparse.ArgumentParser(description="Watch the release loop")
    parser.add_argument("--no-log", action="store_true")
    args = parser.parse_args(argv)

    lines = ["== %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())]
    problems = []

    # Every check is guarded: a watch that dies because one check could not run stops reporting the
    # five it could, and a silent watcher is the failure mode this script exists to remove.
    try:
        timer_findings, repaired = check_timers()
        lines.append("timers: %d/%d active%s" % (
            len(UNITS) - len(timer_findings), len(UNITS),
            ("; started %s" % ", ".join(repaired)) if repaired else ""))
        problems += timer_findings
    except Exception as error:
        lines.append("timers: check failed (%s)" % error)
        problems.append("could not read timers: %s" % error)

    try:
        waiting, blocked = check_queue()
        lines.append("queue: %d waiting, %d blocked" % (len(waiting), len(blocked)))
        if blocked:
            problems.append("%d item(s) parked in blocked/ - the loop could not finish them"
                            % len(blocked))
    except Exception as error:
        lines.append("queue: check failed (%s)" % error)
        problems.append("could not read the work queue: %s" % error)

    try:
        pulls = check_pulls()
        lines.append("pull requests: %s" % (", ".join(pulls) if pulls else "no waits worth reporting"))
        problems += pulls
    except Exception as error:  # the watch must not die because one check could not run
        lines.append("pull requests: check failed (%s)" % error)
        problems.append("could not read pull requests: %s" % error)

    try:
        drift = check_drift()
        lines.append("unpublished commits: %d" % drift)
    except Exception as error:
        lines.append("unpublished commits: check failed (%s)" % error)
        problems.append("could not measure drift: %s" % error)

    try:
        free = check_disk()
        lines.append("free space: %.1f GiB" % free)
        if free < 5:
            problems.append("low disk: %.1f GiB free" % free)
    except Exception as error:
        lines.append("free space: check failed (%s)" % error)
        problems.append("could not read disk usage: %s" % error)

    if problems:
        lines.append("ATTENTION: " + "; ".join(problems))
    else:
        lines.append("healthy")

    text = "\n".join(lines)
    print(text)
    if not args.no_log:
        try:
            os.makedirs(os.path.dirname(LOG), exist_ok=True)
            with open(LOG, "a") as handle:
                handle.write(text + "\n")
        except OSError as error:
            print("ops-watch: could not write %s: %s" % (LOG, error), file=sys.stderr)
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
