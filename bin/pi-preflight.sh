#!/usr/bin/env bash
# pi-preflight.sh - refuse to dispatch an agent when the runtime it needs is not there.
#
# The failure this prevents is silent: `pi` missing, a skill file absent, or the subagent extension
# uninstalled does not stop the worker, it produces a session that cannot do the job and reports
# success in prose. Better to fail before the first token is spent.

set -euo pipefail

REPO=${FLEET_FILTER_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
MIN_VERSION="1.5.0"
MISSING=0

die() { echo "pi-preflight: $*" >&2; MISSING=1; }

PI_BIN=${PI_BIN:-$(command -v pi || echo "${HOME}/.local/bin/pi")}
[ -x "$PI_BIN" ] || die "pi is not executable (looked for ${PI_BIN}); set PI_BIN"
if [ -x "$PI_BIN" ]; then
    printf -v V '%s' "$("$PI_BIN" --version 2>/dev/null | head -1)"
    [ -n "$V" ] || die "pi --version printed nothing"
    # Numeric comparison by sort: the runtime is a dependency, not a suggestion.
    if [ "$(printf '%s\n%s\n' "$MIN_VERSION" "$V" | sort -V | head -1)" != "$MIN_VERSION" ]; then
        die "pi ${V} is older than the required ${MIN_VERSION}"
    fi
    echo "pi-preflight: pi ${V}"
fi

[ -r "${HOME}/.pi/agent/extensions/subagent/index.ts" ] ||
    die "the subagent extension is not installed under ${HOME}/.pi (a release cannot be reviewed without it)"
echo "pi-preflight: subagent extension present"

SKILL=${CVE_WORKER_SKILL:-${REPO}/skills/exploit-signature-pipeline.md}
[ -r "$SKILL" ] || die "the project skill is missing: ${SKILL}"
echo "pi-preflight: skill ${SKILL}"

[ -r "$REPO/bin/exploit-status.py" ] || die "the completion checklist is missing"
echo "pi-preflight: checklist present"

exit "$MISSING"
