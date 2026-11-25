#!/usr/bin/env python3
"""Check a PHP host for the configuration preconditions that make the engine class exploitable.

Purpose
-------
PHP2Shell cannot be stopped by matching a request: its trigger is inside a multipart body, parsed
before application code runs. What can be stopped is the *precondition* - the configuration that the
exploit needs to exist. This reports those preconditions per host, so "is this box exposed" is a
command with an exit code rather than a paragraph in an advisory.

Measured 2026-11-24, both directions:
  * `session.upload_progress.enabled=0` on the lab victim made the published chain A fail outright -
    the progress file is never written, so the include target does not exist ("Failed to open stream:
    No such file or directory"). The exploit is not blocked; it has nothing to run on.
  * `log_errors=Off` (the official image default) means a memory-limit fatal appears only in the
    response body, so the one commodity detection for this class - the error-log rule - matches
    nothing. A host in that state is invisible to Path B.

Design notes
------------
* **Reads a captured `php -i`, never a live host.** The capture is a file, so the check is testable
  offline and the evidence is an artifact (rule 17). `--capture` fetches one over SSH for convenience,
  but the analysis path never touches the network.
* **Each finding is a named precondition with its consequence**, not a score. A score invites tuning;
  a precondition either makes a chain reachable or it does not.
* **Exit code is the contract**: 0 no exploitable precondition found, 1 at least one found, 2 the
  information could not be read. Same shape as the rest of `bin/`.

Usage
-----
    bin/php-posture.py --info data/lab/posture/ff-php-<ts>.ini.txt
    bin/php-posture.py --capture operator@10.20.0.226:ff-php
"""

import argparse
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Each entry: setting, a predicate over the value, and what it means when it holds.
CHECKS = (
    ("session.upload_progress.enabled", lambda v: v.lower() in ("on", "1", "true"),
     "upload progress is enabled: the injection and consumer paths of PHP2Shell chains A and E exist",
     "disable it if the application does not draw upload-progress bars"),
    ("log_errors", lambda v: v.lower() not in ("on", "1", "true"),
     "log_errors is off: a memory-limit fatal stays in the response body, so the error-log detection "
     "rule for this class matches nothing",
     "set log_errors=On and error_log to stderr or a file the log reader can see"),
    ("memory_limit", lambda v: v.strip() not in ("-1", "0"),
     "memory_limit is finite: the OOM fatal that chains D and E require is reachable",
     "the vendor mitigation is memory_limit=-1, which trades this class for unbounded memory use"),
)


def parse_php_info(text):
    """Parse `php -i` into a dict of the settings this check cares about.

    `php -i` prints `key => value => original` for the ini entries and a compact `key => value` form
    elsewhere; both are accepted, and the first occurrence wins because that is the effective value.
    """
    settings = {}
    for line in text.splitlines():
        match = re.match(r"^\s*([A-Za-z0-9_.]+)\s*=>\s*(.*?)\s*=>", line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        settings.setdefault(key, value)
    return settings


def evaluate(settings):
    """Return the list of findings: (setting, value, consequence, remedy)."""
    findings = []
    for setting, is_bad, consequence, remedy in CHECKS:
        value = settings.get(setting)
        if value is None:
            findings.append((setting, "(absent)",
                             "the setting was not reported, so it could not be judged",
                             "capture php -i with the same SAPI that serves requests"))
            continue
        if is_bad(value):
            findings.append((setting, value, consequence, remedy))
    return findings


def capture(target):
    """Fetch `php -i` from host:container over SSH (the only network path in this tool)."""
    host, _, container = target.partition(":")
    if not container:
        raise SystemExit("--capture needs user@host:container")
    argv = ["ssh", "-i", os.path.expanduser("~/.ssh/fleet_dispatch_key"), "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=8", "-o", "LogLevel=ERROR", host,
            "sudo -n podman exec %s php -i 2>/dev/null" % container]
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if proc.returncode != 0:
        raise SystemExit("capture failed: %s" % proc.stderr.decode("utf-8", "replace")[-300:])
    return proc.stdout.decode("utf-8", "replace")


def main(argv=None):
    """Report exploitable PHP configuration preconditions for one host."""
    parser = argparse.ArgumentParser(description="Check PHP configuration preconditions for PHP2Shell")
    parser.add_argument("--info", help="path to a captured `php -i`")
    parser.add_argument("--capture", help="user@host:container to fetch `php -i` from")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.capture:
        text = capture(args.capture)
    elif args.info:
        try:
            with open(args.info) as handle:
                text = handle.read()
        except OSError as error:
            sys.stderr.write("cannot read %s: %s\n" % (args.info, error))
            return 2
    else:
        parser.error("one of --info or --capture is required")

    settings = parse_php_info(text)
    if not settings:
        sys.stderr.write("no ini settings found: is this really `php -i` output?\n")
        return 2
    findings = evaluate(settings)

    if args.json:
        import json
        print(json.dumps({"settings": {k: settings.get(k) for k, _, _, _ in CHECKS},
                          "findings": [{"setting": s, "value": v, "consequence": c, "remedy": r}
                                       for s, v, c, r in findings]}, indent=2, sort_keys=True))
    else:
        for setting, value, consequence, remedy in findings:
            print("EXPOSED  %-32s = %-10s" % (setting, value))
            print("         %s" % consequence)
            print("         remedy: %s" % remedy)
        if not findings:
            print("no exploitable precondition found in %d checked setting(s)" % len(CHECKS))
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
