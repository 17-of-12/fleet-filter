#!/usr/bin/env python3
"""Hostile-input suite for the controller and the responder (Bundle H5).

Purpose
-------
Every value this system stores or forwards originates outside the trust boundary: an Apache
log line, a Wazuh alert, a Fail2ban jail argument, or a header an attacker wrote. Two of the
project's real defects were exactly this class (PT-02, a Wazuh envelope shape the parser did
not expect; PT-10, a client address that silently became the string `(null)`), so "it parsed
on a good input" is not evidence. This suite feeds the shapes that break parsers and asserts
the system either accepts them exactly or refuses them loudly.

Coverage and why each group is here
-----------------------------------
* malformed addresses - `validate_ip` is the only thing standing between a log line and a map
  entry that quarantines the wrong client; it must refuse IPv6, CIDR, ranges, bad octets and
  whitespace variants rather than normalise them silently.
* shell metacharacters and SQL-shaped strings - the same string is stored, rendered into
  shell commands by the Fail2ban / active-response shims, and printed back; an unquoted `;`,
  backtick or `$()` turns a verdict into command execution.
* log injection - a newline inside a stored field forges extra log lines and, worse, extra
  map lines, which is how one claim can quarantine addresses nobody voted for.
* oversized values - a 64 KB field must round-trip rather than be truncated into a different
  identity, because the claim key is built from it.
* forged proxy headers (PT-10) - the responder trusts `X-Tarpit-Client` / `X-Forwarded-For`
  only from a configured trusted proxy, and must not believe a value that is not one clean
  IPv4 address.

Run on any host with the repo present. The live-Apache checks (real request against a running
vhost) live in tests/load and tests/integration; this file is deliberately socket-free so it
can run in CI without a host.
"""

import email.message
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONTROLLER = os.path.join(ROOT, "controller", "adaptive-tarpit.py")
RESPONDER = os.path.join(ROOT, "tarpit", "server", "server.py")
RUNTIME = os.path.basename(sys.executable) or "python"

# SQL-shaped claim sources, kept as constants so the quoting is written once.
SQL_SINGLE = "x'; DROP TABLE claims;--"
SQL_DOUBLE = 'x" OR "1"="1'

failures = []
checks = 0


def check(name, condition, detail=""):
    """Record one assertion; accumulate so one run reports every problem, not the first."""
    global checks
    checks += 1
    if not condition:
        failures.append("%s %s" % (name, detail))


def controller(workdir, args):
    """Invoke the controller against a sandbox db/map so the suite never touches live state.

    Returns `(returncode, stdout, stderr)`; every assertion is expressed in terms of that
    triple rather than by printing, so the same helper serves both the accept and the refuse
    cases. The allowlist file is created empty because the default path is root-owned.
    """
    db = os.path.join(workdir, "state.db")
    amap = os.path.join(workdir, "tarpit-ips.map")
    allow = os.path.join(workdir, "allowlist.conf")
    if not os.path.exists(allow):
        open(allow, "w").close()
    cmd = [sys.executable, CONTROLLER, "--db", db, "--map", amap, "--allowlist", allow] + list(args)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def accepts(ip):
    """Return True when the controller will store `ip` as a claim address."""
    with tempfile.TemporaryDirectory() as workdir:
        return controller(workdir, ["claim", ip, "--verdict", "confirmed", "--source", "sec-test"])[0] == 0


def load_responder():
    """Import the responder module so its logic can be tested without a socket.

    The file is a script, not a package, so it is loaded by path.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("tarpit_server", RESPONDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_addresses():
    """Assert which address strings the controller will and will not quarantine."""
    with tempfile.TemporaryDirectory() as workdir:
        for ip in ["1.2.3.4", "198.51.100.60", "0.0.0.0", "255.255.255.255"]:
            rc, out, err = controller(workdir, ["claim", ip, "--verdict", "confirmed", "--source", "sec-test"])
            check("[%s] accepts %s" % (RUNTIME, ip), rc == 0, err.strip())

        refused = [
            "999.1.1.1", "1.2.3", "1.2.3.4.5", "1.2.3.256", "::1", "fe80::1",
            "1.2.3.4/32", "1.2.3.4/24", "1.2.3.4:80", "1.2.3.4 ", " 1.2.3.4",
            "1.2.3.4\n", "1.2.3.4;rm -rf /", "$(id)", "`id`", "1.2.3.4%00",
            "1.2.3.\u0664", "", "localhost", "1.2.3.04x",
        ]
        for ip in refused:
            rc, out, err = controller(workdir, ["claim", ip, "--verdict", "confirmed", "--source", "sec-test"])
            check("[%s] refuses %r" % (RUNTIME, ip), rc != 0, "accepted: %s" % out.strip())

        # A leading-zero address is accepted by the regex but Apache's txt: map matches the
        # literal string and %{REMOTE_ADDR} never renders a leading zero, so the claim is
        # unenforceable. Pinned so a future change is a decision, not a surprise.
        check("[%s] documents leading-zero acceptance (1.2.3.04)" % RUNTIME, accepts("1.2.3.04"),
              "behaviour changed: the controller now rejects a form it used to store")

        # One bad address in a batch must fail the whole command rather than half-apply.
        rc, out, err = controller(workdir, ["claim", "10.0.0.1", "999.0.0.1", "--verdict", "suspect"])
        check("[%s] rejects the whole batch when one address is bad" % RUNTIME, rc != 0, out + err)
        rc, out, _ = controller(workdir, ["list", "--json"])
        check("[%s] no partial write from the rejected batch" % RUNTIME, "10.0.0.1" not in out,
              "10.0.0.1 was stored even though the command failed")


def test_metacharacters_and_injection():
    """Assert hostile `--source` values are stored as data and round-trip byte-exactly.

    Each value gets its own sandbox db: the controller folds several claims for one address
    into a single row (`claims` is a count, not a list), so a shared db would only ever
    surface one source and the remaining assertions would be vacuous.
    """
    hostile = [
        "sig;rm -rf /tmp",
        "sig`id`",
        "sig$(id)",
        "sig a b",
        "sig\ttab",
        "sig\\backslash",
        "sig'quote",
        'sig"dquote',
        SQL_SINGLE,
        SQL_DOUBLE,
        "sig\nsecond-line",
        "A" * 65536,
    ]
    for value in hostile:
        label = value if len(value) <= 24 else "a %d-char string" % len(value)
        with tempfile.TemporaryDirectory() as workdir:
            rc, _out, err = controller(workdir, ["claim", "192.0.2.10", "--verdict", "confirmed",
                                                  "--source", value])
            check("[%s] stores %r without error" % (RUNTIME, label), rc == 0, err.strip())
            if rc != 0:
                continue
            rc2, out2, err2 = controller(workdir, ["list", "--json"])
            check("[%s] queryable after storing %r" % (RUNTIME, label), rc2 == 0, err2.strip())
            if rc2 != 0:
                continue
            try:
                rows = json.loads(out2)
            except ValueError as exc:
                check("[%s] list --json is valid JSON after %r" % (RUNTIME, label), False, str(exc))
                continue
            check("[%s] exactly one row after storing %r" % (RUNTIME, label),
                  len(rows) == 1 and rows[0].get("ip") == "192.0.2.10", "rows: %d" % len(rows))
            check("[%s] %r round-trips byte-exactly" % (RUNTIME, label),
                  rows[0].get("source") == value,
                  "stored %r" % (rows[0].get("source", "")[:40],))

    # The store must survive SQL-shaped values: parameter queries make them data, but a
    # future string-interpolated query would silently lose rows.
    with tempfile.TemporaryDirectory() as workdir:
        controller(workdir, ["claim", "198.51.100.20", "--verdict", "suspect", "--source", SQL_SINGLE])
        controller(workdir, ["claim", "198.51.100.21", "--verdict", "suspect", "--source", SQL_DOUBLE])
        rc, out, err = controller(workdir, ["list", "--json"])
        check("[%s] store intact after SQL-shaped sources" % RUNTIME,
              rc == 0 and "198.51.100.20" in out and "198.51.100.21" in out, err.strip())


def test_responder_attribution():
    """Assert the responder only believes a proxy-supplied client address when it may (PT-10).

    The header is attacker-writable on any request that reaches Apache directly, so trusting
    it unconditionally lets a client choose which address gets quarantined. `TarpitHandler
    ._client_ip` is called unbound with a stand-in object, the only way to test the decision
    without a socket per case.

    One divergence used to exist and is now closed: the responder's address check accepted
    `999.1.1.1` - and, before it moved to \\A/\\Z with an explicit [0-9] class, a trailing
    newline and Unicode digits - while the controller's `validate_ip` refused those, so the
    responder reported a client the controller would not store. Both now apply the same rule,
    asserted below.
    """
    mod = load_responder()
    handler_cls = getattr(mod, "TarpitHandler", None)
    if handler_cls is None:
        check("[%s] responder exposes TarpitHandler" % RUNTIME, False, "class missing")
        return

    class Fake(object):
        """Minimal stand-in for TarpitHandler: only the attributes _client_ip reads.

        `trusted_proxies` is copied from the class so the stand-in exercises the same trust
        list the deployed responder uses, rather than an empty one that would make every
        header-rejection case pass for the wrong reason.
        """

        def __init__(self, peer, headers):
            """Populate only the three attributes `_client_ip` reads: peer, trust list, headers."""
            self.client_address = (peer, 41234)
            self.trusted_proxies = handler_cls.trusted_proxies
            self.headers = email.message.Message()
            for name, value in headers.items():
                self.headers[name] = value

    # (peer, headers, expected) - 127.0.0.1 and ::1 are the default trusted proxies.
    cases = [
        ("198.51.100.77", {}, "198.51.100.77"),
        ("127.0.0.1", {"X-Tarpit-Client": "198.51.100.77"}, "198.51.100.77"),
        ("198.51.100.77", {"X-Tarpit-Client": "1.2.3.4"}, "198.51.100.77"),      # forged, ignored
        ("127.0.0.1", {"X-Forwarded-For": "9.9.9.9, 1.2.3.4"}, "1.2.3.4"),    # last hop wins
        ("198.51.100.77", {"X-Forwarded-For": "1.2.3.4"}, "198.51.100.77"),     # forged, ignored
        ("127.0.0.1", {"X-Tarpit-Client": "not-an-ip"}, "127.0.0.1"),         # rejected -> peer
        ("127.0.0.1", {"X-Tarpit-Client": "1.2.3.4, 5.6.7.8"}, "127.0.0.1"),  # two addresses
        ("127.0.0.1", {"X-Tarpit-Client": "1.2.3.4/32"}, "127.0.0.1"),        # CIDR rejected
        ("127.0.0.1", {"X-Tarpit-Client": " 1.2.3.4 "}, "1.2.3.4"),           # whitespace trimmed
        ("127.0.0.1", {}, "127.0.0.1"),
        ("::1", {"X-Tarpit-Client": "1.2.3.4"}, "1.2.3.4"),                    # ::1 also trusted
        ("203.0.113.9", {"X-Tarpit-Client": "1.2.3.4", "X-Forwarded-For": "5.6.7.8"}, "203.0.113.9"),
    ]
    for peer, headers, expected in cases:
        got = handler_cls._client_ip(Fake(peer, headers))
        check("[%s] %s %r -> %s" % (RUNTIME, peer, headers, expected),
              got == expected, "got %r" % (got,))

    # The two validators must agree on an out-of-range octet: the responder falls back to the
    # peer address and the controller refuses to store it.
    check("[%s] responder rejects 999.1.1.1 and falls back to the peer" % RUNTIME,
          handler_cls._client_ip(Fake("127.0.0.1", {"X-Tarpit-Client": "999.1.1.1"})) == "127.0.0.1")
    check("[%s] controller refuses that same address" % RUNTIME, accepts("999.1.1.1") is False)
    # The newline case is tested on the validator itself: `email.message` normalises an
    # embedded newline when a header is set, so a header-based case would not exercise it.
    check("[%s] responder validator rejects a trailing-newline address" % RUNTIME,
          mod.valid_ipv4("1.2.3.4\n") is False)
    check("[%s] responder validator rejects a Unicode-digit address" % RUNTIME,
          mod.valid_ipv4("1.2.3.\u0664") is False)
    check("[%s] responder validator accepts a normal address" % RUNTIME,
          mod.valid_ipv4("198.51.100.60") is True)


def main():
    """Run every hostile-input check on this interpreter and print a summary."""
    test_addresses()
    test_metacharacters_and_injection()
    test_responder_attribution()
    if failures:
        for failure in failures:
            print("FAIL", failure)
        print("FAIL checks: %d passed, %d failed" % (checks - len(failures), len(failures)))
        return 1
    print("PASS checks: %d passed, 0 failed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
