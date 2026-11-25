#!/bin/sh
# ensure-testnet-addrs.sh - make the project's TEST-NET addresses exist on `lo`, idempotently.
#
# Purpose
# -------
# Fleet-Filter binds test listeners and synthetic clients to TEST-NET addresses
# (198.18.0.0/15) on lab-web01 instead of loopback aliases, because Wazuh's `firewall-drop`
# active response has previously installed DROP rules against loopback test addresses and
# locked the harness out (measured 2026-11-13). Those addresses were created ad hoc with
# `ip addr add` in earlier sessions and are not persistent, so a reboot silently removes every
# address the vhosts bind to - and an Apache `Listen` on a missing address does not warn, it
# fails to start, taking the real application's :443 vhost down with the test vhost.
#
# This script is the persistence mechanism: a declarative address list plus an idempotent
# reconciler, run at boot before httpd (see systemd/fleet-filter-testnet-addr.service).
#
# Design notes
# ------------
# * Additive only. Addresses present on lo but absent from the list are left alone, so this
#   script can never delete an address another operator or an earlier run depends on.
# * `ip addr show dev lo` is parsed once rather than per address, so the cost does not scale
#   with the list.
# * `/32` is appended when an entry has no prefix, because `ip addr add 198.51.100.110` fails
#   while `ip addr add 198.51.100.110/32` succeeds.
#
# Usage: ensure-testnet-addrs.sh [--file PATH] [--dev lo] [--dry-run]
# Exit:  0 all requested addresses present | 1 an add failed | 2 bad usage/config

set -eu

DEFAULT_FILE="/etc/fleet-filter/testnet-addr"
FILE=""
DEV="lo"
DRY=0

usage() {
    echo "usage: $0 [--file PATH] [--dev lo] [--dry-run]" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --file) FILE="$2"; shift 2 ;;
        --dev) DEV="$2"; shift 2 ;;
        --dry-run) DRY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

if [ -z "$FILE" ]; then
    if [ -r "$DEFAULT_FILE" ]; then
        FILE="$DEFAULT_FILE"
    elif [ -r "$(dirname "$0")/../config/testnet-addr" ]; then
        FILE="$(dirname "$0")/../config/testnet-addr"
    else
        echo "error: no address list (looked for $DEFAULT_FILE and ../config/testnet-addr)" >&2
        exit 2
    fi
fi
[ -r "$FILE" ] || { echo "error: cannot read $FILE" >&2; exit 2; }

# Collect the addresses already present on the target interface, in one call.
present="$(ip -4 addr show dev "$DEV" 2>/dev/null | awk '{print $2}')"
[ -n "$present" ] || { echo "error: interface $DEV has no IPv4 addresses or does not exist" >&2; exit 1; }

added=0
already=0
failed=0
# `#` comments (whole-line and trailing) and blank lines are ignored; each remaining field is
# one address. Stripping the comment before splitting matters: `tr -d '[:space:]'` on a line
# like `198.51.100.110    # backend vhost` glues the comment onto the address.
for entry in $(sed -e 's/#.*$//' "$FILE" | tr -s '[:space:]' '\n' | grep -v '^$'); do
    [ -n "$entry" ] || continue
    case "$entry" in
        */*) addr="$entry" ;;
        *)   addr="$entry/32" ;;
    esac
    if printf '%s\n' "$present" | grep -qxF "$addr"; then
        already=$((already + 1))
        continue
    fi
    if [ "$DRY" -eq 1 ]; then
        echo "would add $addr on $DEV"
        added=$((added + 1))
        continue
    fi
    if ip addr add "$addr" dev "$DEV" 2>/dev/null; then
        echo "added $addr on $DEV"
        added=$((added + 1))
    else
        echo "FAILED to add $addr on $DEV" >&2
        failed=$((failed + 1))
    fi
done

echo "summary: $added added, $already already present, $failed failed (file: $FILE)"
[ "$failed" -eq 0 ] || exit 1
