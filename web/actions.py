#!/usr/bin/env python3
"""Y2: the console's only write path - setting one host's emergency bypass over SSH.

Everything else in `web/` is a reader. This module exists as a separate file so the read-only
default is provable rather than a matter of trust: `web/app.py` only imports and calls it when the
server was started with `--allow-actions`, and the deployed default is that the flag is off, which
means a read-only console has no code path that can mutate a fleet host.

Three rules make the write safe enough to expose in a browser:

1. **The target must be registered.** The host is looked up in the registry rather than taken on
   trust, so the SSH destination can never be shaped by the request body into something else.
2. **The actor must be a real identity.** The actor comes from the `X-Forwarded-User` header Apache
   sets after basic authentication. An unauthenticated caller arrives as `anonymous`, and
   `anonymous` is refused - the controller's audit line is the record of who disabled enforcement,
   and recording `anonymous` there would defeat the point of the TTL-and-reason design.
3. **Arguments are validated before they are quoted.** `shlex.quote` protects the remote shell, but
   validating `state` against a closed set and `ttl` against an integer range first means a
   malformed request is rejected with a reason instead of being shipped to a remote host to fail.

Python 3.6+ (the interpreter on the control node is 3.9; targets may be older).
"""

from __future__ import print_function

import html as html_module
import shlex

DEFAULT_CONTROLLER_BIN = "/usr/local/bin/adaptive-tarpit"
ALLOWED_STATES = ("on", "off")
MIN_TTL = 60
MAX_TTL = 604800  # 7 days: longer than this should be a decision, not a form field
MIN_REASON = 3
RUNNER_TIMEOUT = 60  # seconds an ssh action may run before the console stops waiting on it


class ActionError(Exception):
    """Raised when a requested action is invalid; the message is shown to the operator."""


def field_value(form, name):
    """Read one field from a parsed form, tolerating both `{k: [v]}` and `{k: v}` shapes."""
    values = form.get(name) or []
    if isinstance(values, list):
        return (values[0] if values else "").strip()
    return str(values).strip()


def normalise(form, registry_hosts, controller_bin=None):
    """Validate a submitted form and return the normalised action, or raise ActionError.

    `form` is the parsed POST body, `registry_hosts` is the set of FQDNs the console knows about.
    Validation lives here, in one place, so the executor and the UI cannot disagree about what a
    valid request looks like.
    """
    host = field_value(form, "host")
    state = field_value(form, "state")
    reason = field_value(form, "reason")
    ttl_raw = field_value(form, "ttl")

    if not host:
        raise ActionError("no host selected")
    if host not in registry_hosts:
        raise ActionError("%s is not in the install registry" % host)
    if state not in ALLOWED_STATES:
        raise ActionError("state must be 'on' or 'off' (got %r)" % state)

    ttl = None
    if state == "on":
        if not ttl_raw:
            raise ActionError("bypass on requires a TTL, so enforcement cannot be left off by accident")
        try:
            ttl = int(ttl_raw)
        except ValueError:
            raise ActionError("ttl must be an integer number of seconds (got %r)" % ttl_raw)
        if not MIN_TTL <= ttl <= MAX_TTL:
            raise ActionError("ttl must be between %d and %d seconds" % (MIN_TTL, MAX_TTL))
        if len(reason) < MIN_REASON:
            raise ActionError("a reason is required when turning bypass on "
                              "(%d characters minimum)" % MIN_REASON)
    return {
        "host": host,
        "state": state,
        "ttl": ttl,
        "reason": reason or ("cleared from console" if state == "off" else ""),
        "controller_bin": controller_bin or DEFAULT_CONTROLLER_BIN,
    }


def ssh_target(ssh_user, host):
    """Build the SSH destination for a registered host, refusing an unusable user."""
    if not ssh_user:
        raise ActionError("%s has no ssh_user in the registry" % host)
    return "%s@%s" % (ssh_user, host)


def build_command(action, actor):
    """Render the remote command as an argv list, quoting every value that came from the form.

    `sudo -n` (non-interactive) is deliberate: the controller is root-owned and the console
    authenticates as the SSH user, so if that user cannot sudo without a password the command fails
    immediately instead of hanging a request thread waiting at a prompt.
    """
    remote = "sudo -n %s bypass %s" % (shlex.quote(action["controller_bin"]), action["state"])
    if action["state"] == "on":
        remote += " --ttl %d --reason %s" % (int(action["ttl"]), shlex.quote(action["reason"]))
    remote += " --actor %s" % shlex.quote(actor)
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            ssh_target(action["ssh_user"], action["host"]), remote]


def execute(form, installs, actor, runner=None, controller_bin=None):
    """Validate a submitted form and run it against the target host.

    Returns the normalised action plus `rc` and `output` from the remote command. `runner` defaults
    to a real subprocess call and is injectable, so the validation and command-construction rules
    are testable without touching the network.
    """
    registry = dict((i["fqdn"], i) for i in installs)
    action = normalise(form, set(registry), controller_bin)
    if not actor or actor == "anonymous":
        raise ActionError("actions require an authenticated identity; this request arrived as anonymous")
    action["actor"] = actor
    action["ssh_user"] = registry[action["host"]].get("ssh_user") or ""
    rc, output = (runner or default_runner)(build_command(action, actor))
    action["rc"] = rc
    action["output"] = output
    return action


def default_runner(command, timeout=RUNNER_TIMEOUT):
    """Run an argv list and return (exit_code, combined_output) without raising on failure.

    The timeout is the point, not an extra: `communicate()` without one blocks the request thread for
    as long as the remote shell holds the connection open, so an ssh session that authenticated but
    never exited pinned a console thread permanently while the operator's browser simply spun. A
    timeout is reported the way a failed command is - non-zero exit plus the reason - so the result
    page can say what happened instead of never arriving.
    """
    import subprocess
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        output = proc.communicate(timeout=timeout)[0]
    except subprocess.TimeoutExpired:
        proc.kill()
        output = proc.communicate()[0]
        detail = output.decode("utf-8", "replace").strip()
        return 124, "\n".join(part for part in (
            detail, "console: remote command timed out after %ds" % timeout) if part)
    return proc.returncode, output.decode("utf-8", "replace").strip()


def render_result(action):
    """Render the outcome page for one executed action as (tone, body_html_lines)."""
    tone = "ok" if action["rc"] == 0 else "bad"
    lines = ['<h1>Bypass %s &middot; %s</h1>' % (html_module.escape(action["state"]),
                                                 html_module.escape(action["host"])),
             '<p class="sub">actor <code>%s</code>%s</p>' % (
                 html_module.escape(action["actor"]),
                 "" if action["ttl"] is None else " &middot; ttl %ds" % action["ttl"]),
             '<div class="panel"><pre>%s</pre></div>' % html_module.escape(action["output"] or "(no output)")]
    return tone, lines
