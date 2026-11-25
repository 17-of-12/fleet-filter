#!/usr/bin/env python3
"""Checks for the PHP-fatal filter, against lines captured from a live mod_php victim.

Purpose
-------
PHP2Shell's trigger is in the multipart body, so this error-log line is the only commodity
observable the class leaves behind - and only when `log_errors = On`. The filter is therefore
load-bearing for the engine class, which is exactly the reason to pin it to real bytes rather than to
a pattern that merely compiles. `tests/fixtures/php-fatal-error-lines.log` holds two measured fatals,
one unrelated notice, the access-log line the same request produced, and an Apache startup line.

What this does not prove: fail2ban's own `<HOST>` substitution and `datepattern` handling. Matching
here uses the same address shape fail2ban substitutes; `fail2ban-regex` on a host with the filter
installed remains the authority before a jail is enabled.

Runs under Python 3.6+ with no third-party modules.
"""

from __future__ import print_function

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "php-fatal-error-lines.log")
FILTER = os.path.join(ROOT, "detector", "fail2ban", "filter.d", "php-fatal.conf")

PASS = 0
FAIL = 0


def check(condition, label):
    """Record one assertion, printing ok/FAIL so the shell harness can read the result."""
    global PASS, FAIL
    if condition:
        PASS += 1
        print("ok   %s" % label)
    else:
        FAIL += 1
        print("FAIL %s" % label)


def load_failregex(path):
    """Read the `failregex = ...` line(s) out of a fail2ban filter file."""
    patterns = []
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if line.startswith("failregex"):
                patterns.append(line.split("=", 1)[1].strip())
    return patterns


def to_python(pattern):
    """Translate the one fail2ban token used here into a named group."""
    return pattern.replace("<HOST>", "(?P<host>\\S+)")


patterns = load_failregex(FILTER)
check(bool(patterns), "the filter declares a failregex")
check("log_errors" in open(FILTER).read(),
      "the filter records its configuration dependency (log_errors) in the file, not only in a README")

lines = [line.rstrip("\n") for line in open(FIXTURE) if line.strip()]
for pattern in patterns:
    regex = re.compile(to_python(pattern))
    fatals = [line for line in lines if "PHP Fatal error" in line]
    others = [line for line in lines if "PHP Fatal error" not in line]
    matched = [line for line in lines if regex.search(line)]
    check(len(matched) == len(fatals),
          "every fatal line matches and nothing else does (%d of %d)" % (len(matched), len(fatals)))
    check(all(regex.search(line) for line in fatals), "each measured fatal matches individually")
    check(not any(regex.search(line) for line in others),
          "the notice, the access line and the startup line do not match")
    host = regex.search(fatals[0]).groupdict().get("host")
    check(host == "10.20.1.148", "the client address is captured for the ban (%r)" % host)

print("\ntest_fail2ban_php_fatal.py: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
