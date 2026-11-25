#!/usr/bin/env python3
"""Tests for the console's gated write path in web/actions.py (Bundle Y2).

The console is read-only by default, so the properties worth testing are the ones that keep it that
way until someone opts in: which requests are accepted at all, what command an accepted request
becomes, and that a rejected request never reaches the network. `runner` is injectable precisely so
these can be asserted without SSHing anywhere.

Runs under Python 3.9 and 3.12; needs no third-party modules.
"""

from __future__ import print_function

import base64
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

SPEC = importlib.util.spec_from_file_location("pt_actions", os.path.join(ROOT, "web", "actions.py"))
actions = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(actions)

PASS = 0
FAIL = 0
CALLS = []


def check(condition, label):
    """Record one assertion."""
    global PASS, FAIL
    if condition:
        PASS += 1
        print("ok   %s" % label)
    else:
        FAIL += 1
        print("FAIL %s" % label)


def fake_runner(command):
    """Record the argv it was handed and pretend the remote command succeeded."""
    CALLS.append(list(command))
    return 0, "bypass ON for 3600s (until 2026-11-15T12:00:00Z) - drill"


def form(**fields):
    """Build a parsed POST body in the `{key: [value]}` shape parse_qs produces."""
    return dict((k, [v]) for k, v in fields.items())


INSTALLS = [{"fqdn": "lab-web01.lab", "ssh_user": "agent", "stage": "2+3-canary"},
            {"fqdn": "build01.lab", "ssh_user": "agent", "stage": "control"}]
REGISTRY = set(i["fqdn"] for i in INSTALLS)

# --- normalise: the validation surface -----------------------------------------------------------
good = actions.normalise(form(host="lab-web01.lab", state="on", ttl="3600",
                             reason="load test"), REGISTRY)
check(good["host"] == "lab-web01.lab" and good["state"] == "on" and good["ttl"] == 3600,
      "a valid `on` request normalises to host/state/ttl")
check(good["controller_bin"] == actions.DEFAULT_CONTROLLER_BIN,
      "the controller binary defaults to the documented path")

for label, fields in [
    ("empty host is rejected", dict(host="", state="on", ttl="3600", reason="drill")),
    ("unregistered host is rejected", dict(host="rogue.example.com", state="on", ttl="3600",
                                           reason="drill")),
    ("unknown state is rejected", dict(host="lab-web01.lab", state="maybe", ttl="3600",
                                       reason="drill")),
    ("`on` without a ttl is rejected", dict(host="lab-web01.lab", state="on", reason="drill")),
    ("non-integer ttl is rejected", dict(host="lab-web01.lab", state="on", ttl="soon",
                                         reason="drill")),
    ("ttl below the minimum is rejected", dict(host="lab-web01.lab", state="on", ttl="5",
                                               reason="drill")),
    ("ttl above the maximum is rejected", dict(host="lab-web01.lab", state="on",
                                               ttl="99999999", reason="drill")),
    ("`on` without a reason is rejected", dict(host="lab-web01.lab", state="on",
                                               ttl="3600", reason="x")),
]:
    try:
        actions.normalise(fields, REGISTRY)
        check(False, label)
    except actions.ActionError:
        check(True, label)

off = actions.normalise(form(host="build01.lab", state="off"), REGISTRY)
check(off["ttl"] is None and off["reason"] == "cleared from console",
      "`off` needs no ttl or reason and gets a sensible default reason")

# --- build_command: what an accepted request becomes ---------------------------------------------
cmd = actions.build_command(dict(off, ssh_user="agent", actor="admin"), "admin")
check(cmd[0] == "ssh" and "BatchMode=yes" in cmd, "the command is a non-interactive ssh invocation")
check("agent@build01.lab" in cmd, "the ssh target is built from the registry, not the form")
remote = cmd[-1]
check(remote.startswith("sudo -n %s bypass off" % actions.DEFAULT_CONTROLLER_BIN),
      "the remote command invokes the controller's bypass verb through sudo -n")

hostile = actions.normalise(form(host="lab-web01.lab", state="on", ttl="600",
                                reason="x; rm -rf /"), REGISTRY)
hostile_cmd = actions.build_command(dict(hostile, ssh_user="agent"), "admin")
check("'x; rm -rf /'" in hostile_cmd[-1],
      "shell metacharacters in the reason are quoted, not passed through")
check("--actor admin" in hostile_cmd[-1], "the actor is passed to the controller")
check("--actor 'ad;min'" in actions.build_command(dict(off, ssh_user="agent"), "ad;min")[-1],
      "an actor containing shell metacharacters is quoted (shlex quotes only what needs it)")

# --- execute: gating and the no-network-on-rejection property ------------------------------------
del CALLS[:]
try:
    actions.execute(form(host="lab-web01.lab", state="on", ttl="3600", reason="drill"),
                    INSTALLS, "anonymous", runner=fake_runner)
    check(False, "an anonymous actor is refused")
except actions.ActionError:
    check(True, "an anonymous actor is refused")
check(CALLS == [], "a refused action never invokes the runner (no SSH on rejection)")

result = actions.execute(form(host="lab-web01.lab", state="on", ttl="3600", reason="drill"),
                         INSTALLS, "admin", runner=fake_runner)
check(len(CALLS) == 1 and result["rc"] == 0, "an accepted action runs exactly one command")
check(result["output"].startswith("bypass ON for 3600s"), "the remote output is returned for display")
check(result["actor"] == "admin", "the actor is carried on the result")

del CALLS[:]
try:
    actions.execute(form(host="not.registered", state="off"), INSTALLS, "admin", runner=fake_runner)
    check(False, "an unregistered host is refused before any command runs")
except actions.ActionError:
    check(True, "an unregistered host is refused before any command runs")
check(CALLS == [], "an unregistered host never reaches the runner")

# --- render_result --------------------------------------------------------------------------------
ok_tone, ok_body = actions.render_result({"state": "on", "host": "lab-web01.lab",
                                          "actor": "admin", "ttl": 3600, "rc": 0,
                                          "output": "bypass ON"})
check(ok_tone == "ok" and "Bypass on &middot; lab-web01.lab" in ok_body[0],
      "a successful action renders with the ok tone and names the host")
bad_tone, _ = actions.render_result({"state": "off", "host": "h", "actor": "admin", "ttl": None,
                                     "rc": 1, "output": "sudo: a password is required"})
check(bad_tone == "bad", "a non-zero exit renders with the bad tone rather than as success")

# --- authenticated_user (web/app.py): who the console thinks is acting ----------------------------
sys.path.insert(0, os.path.join(ROOT, "web"))
APP_SPEC = importlib.util.spec_from_file_location("pt_app", os.path.join(ROOT, "web", "app.py"))
pt_app = importlib.util.module_from_spec(APP_SPEC)
APP_SPEC.loader.exec_module(pt_app)
BASIC = "Basic " + base64.b64encode(b"admin:pw").decode("ascii")

check(pt_app.authenticated_user({}) == "anonymous", "no headers at all resolves to anonymous")
check(pt_app.authenticated_user({"X-Forwarded-User": "admin"}) == "admin",
      "a forwarded X-Forwarded-User header is the identity")
check(pt_app.authenticated_user({"X-Forwarded-User": "(null)", "Authorization": BASIC}) == "admin",
      "Apache's literal `(null)` placeholder is ignored in favour of the Basic credential")
check(pt_app.authenticated_user({"X-Forwarded-User": "(null)"}) == "anonymous",
      "a `(null)` header with no credential is anonymous, not a user named `(null)`")
check(pt_app.authenticated_user({"Authorization": BASIC}) == "admin",
      "a Basic credential is decoded for its username")
check(pt_app.authenticated_user({"Authorization": "Bearer tok"}) == "anonymous",
      "a non-Basic Authorization header is not an identity")
check(pt_app.authenticated_user({"Authorization": "Basic !!!not-base64!!!"}) == "anonymous",
      "a malformed Basic credential is anonymous rather than an exception")

# --- default_runner (web/app.py's write path executor): timeouts must not hang a request -----------
# The runner used to call communicate() with no timeout, so an ssh session that authenticated but
# never exited pinned a console thread forever and the browser never got a page.
rc, output = actions.default_runner(["sh", "-c", "echo hello"], timeout=10)
check(rc == 0 and output == "hello", "the default runner returns the command's exit code and output")

rc, output = actions.default_runner(["sh", "-c", "echo partial; sleep 5"], timeout=1)
check(rc == 124, "a timed-out command reports exit code 124 rather than never returning")
check(b"timed out" in output.encode() if isinstance(output, str) else b"timed out" in output,
      "the timeout is explained in the output the operator sees")
check("partial" in output, "output produced before the timeout is kept, not discarded")

rc, output = actions.default_runner(["sh", "-c", "echo oops >&2; exit 3"], timeout=10)
check(rc == 3 and "oops" in output,
      "a failing command's stderr is captured into the same output the page renders")

print("test_actions.py: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
