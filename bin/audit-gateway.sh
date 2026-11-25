#!/bin/sh
# audit-gateway.sh - shell entry point for the gateway dependency audit (ADR-0001 M6).
#
# Exists so a build pipeline, a systemd timer, or a person all invoke the same audit with the
# same arguments. The logic lives in audit-gateway.py, which prefers `cargo audit` when the
# binary is present and otherwise queries the RustSec advisory database directly (and records
# which method it used, so a fallback result never looks like a cargo-audit result).
#
# Usage: bin/audit-gateway.sh [--lockfile PATH] [--out DIR] [--quiet]
# Exit:  0 no unwaived finding | 1 findings exist | 2 audit could not be completed
set -eu
exec python3.9 "$(dirname "$0")/audit-gateway.py" "$@"
