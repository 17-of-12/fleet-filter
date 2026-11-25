#!/usr/bin/env python3
"""Checks for the Path B fail2ban filter against real access-log bytes.

Purpose
-------
The filter's failregex is a Python-style regular expression that fail2ban runs against an access
log, and the project's own research record contains a failregex that matched **0 of 3809** real
combined-log lines (`docs/` and the SKILL.md syntax facts). A pattern that compiles is not a pattern
that matches; only lines from the log it will actually read can answer that.

So this file's oracle is `tests/fixtures/fail2ban-access-lines.log`: three lines captured verbatim
from the `ff-httpd:2.4.49` victim on ff-apache02 on 2026-11-24, including the two CVE-2021-41773
traversal requests. If a later edit narrows the pattern so those stop matching, this fails.

What it does not prove: fail2ban's own substitution of `<HOST>`. The fixture is matched with the
same address group fail2ban uses (`\\S+`), which catches the shape of the substitution but cannot
reproduce fail2ban's parsing of its own config. `fail2ban-regex` on a host with the filter installed
is still the authority before a jail is enabled.

Runs under Python 3.6+ with no third-party modules.
"""

from __future__ import print_function

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # tests/unit -> repo root
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "fail2ban-access-lines.log")
FILTER = os.path.join(ROOT, "detector", "fail2ban", "filter.d", "fleet-filter.conf")

PASS = 0
FAIL = 0


def check(condition, label):
    """Record one assertion, printing ok/FAIL so a shell harness can read the result."""
    global PASS, FAIL
    if condition:
        PASS += 1
        print("ok   %s" % label)
    else:
        FAIL += 1
        print("FAIL %s" % label)


def filter_regex(path):
    """Extract the single `failregex =` line from the filter file, or raise.

    The filter ships exactly one pattern on purpose: fail2ban ORs several patterns together, and a
    second one is how a "small fix" silently widens what counts as a failure.
    """
    patterns = []
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if line.startswith("failregex"):
                patterns.append(line.split("=", 1)[1].strip())
    if len(patterns) != 1:
        raise SystemExit("expected exactly one failregex line, found %d" % len(patterns))
    return patterns[0]


def compiled(pattern):
    """Compile the shipped pattern with `<HOST>` replaced the way fail2ban replaces it."""
    return re.compile(pattern.replace("<HOST>", r"\S+"))


with open(FIXTURE) as handle:
    lines = [line for line in handle if line.strip()]

pattern = filter_regex(FILTER)
regex = compiled(pattern)

check("500" in pattern, "the counted status set includes 500 (an exploit that errors is not invisible)")
check("403" not in pattern, "403 stays uncounted, so tarpitted clients cannot count their own answers")

matched = [line for line in lines if regex.search(line)]
check(len(lines) == 3, "the fixture is the three captured lines, not a growing archive")
check(len(matched) == 3, "all three captured lines match (found %d)" % len(matched))
check(any('"GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1" 500' in line for line in matched),
      "the GET traversal that reached the vulnerable CGI path is counted")
check(any('"POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1" 500' in line for line in matched),
      "the POST traversal (the form that can execute a command) is counted")
check(any('"GET /nope-404 HTTP/1.1" 404' in line for line in matched),
      "an ordinary 404 is still counted, as it was before the change")

# The change is load-bearing, not cosmetic: the pre-2026-11-24 status set missed both exploit
# lines in these exact bytes. Without this assertion the test would pass with the old pattern too,
# which is the definition of a check that cannot fail.
before = compiled(pattern.replace("(400|401|404|405|500)", "(400|401|404|405)"))
missed_before = [line for line in lines if not before.search(line)]
check(len(missed_before) == 2,
      "the old status set missed both traversal lines (found %d)" % len(missed_before))
check(all('500' in line for line in missed_before),
      "the missed lines are exactly the 500s - the detector's blind spot, reproduced")

# The filter must not depend on the fields after the User-Agent: the lab's LogFormat appends
# `ct= cl= ho= proto=`, a production combined log does not, and a pattern anchored to the end would
# work on one and not the other.
plain = ('192.0.2.10 - - [24/Nov/2026:14:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 123 '
         '"-" "Mozilla/5.0"')
check(bool(regex.search(plain)), "a plain combined-format line matches, with no extra fields")

# A line whose status is a 3xx must not match: a redirect is not a failed probe.
check(not regex.search(plain.replace(" 404 ", " 302 ")), "a 302 line does not match")

# Traffic from our own tarpit answers 403 and must never count.
check(not regex.search(plain.replace(" 404 ", " 403 ")), "a 403 line does not match")

print("\ntest_fail2ban_filter.py: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
