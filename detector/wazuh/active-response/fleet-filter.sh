#!/bin/sh
# ---------------------------------------------------------------------------
# fleet-filter.sh - Wazuh Active Response entrypoint for Fleet-Filter.
#
# Wazuh executes /var/ossec/active-response/bin/<executable> for an AR request and
# hands it the alert JSON on stdin (older agents also pass it as argv[1]). This
# script is deliberately a thin shim: every decision lives in the controller, so
# the AR path and the future API-poller path cannot drift apart.
#
# Anything this script prints to stdout/stderr is appended by the agent to
# /var/ossec/logs/active-responses.log, which is the audit trail for AR activity.
# ---------------------------------------------------------------------------
set -eu

AT="${AT_BIN:-${ADAPTIVE_TARPIT_BIN:-/usr/local/bin/adaptive-tarpit}}"
[ -x "$AT" ] || { echo "fleet-filter: $AT not found or not executable" >&2; exit 66; }

# Non-default store/map locations (used by tests and by any host whose paths differ);
# these mirror the controller's own defaults so the flags are always well-formed.
DB="${ADAPTIVE_TARPIT_DB:-/var/lib/adaptive-tarpit/state.db}"
MAP="${ADAPTIVE_TARPIT_MAP:-/etc/httpd/tarpit-ips.map}"
ALLOWLIST="${ADAPTIVE_TARPIT_ALLOWLIST:-/etc/adaptive-tarpit/allowlist}"

# Prefer stdin; fall back to argv[1] for agents that pass the payload as an argument.
argv_payload="${1:-}"
if [ -t 0 ]; then
    payload=""
else
    payload=$(cat 2>/dev/null || true)
fi
if [ -z "$payload" ] && [ -n "$argv_payload" ]; then
    payload=$argv_payload
fi
if [ -z "$payload" ]; then
    echo "fleet-filter: no alert JSON on stdin or argv[1]" >&2
    exit 64
fi

# --render keeps the Apache map current on every accepted claim. The controller's
# render is idempotent, so a duplicate claim does not rewrite the file. The positional
# argv is not forwarded: once the payload is on stdin the controller needs no other
# arguments, and `ingest` takes no positionals. Global options must precede the
# subcommand - argparse rejects them after it.
set -- --db "$DB" --map "$MAP" --allowlist "$ALLOWLIST" ingest --render
printf '%s' "$payload" | "$AT" "$@"
