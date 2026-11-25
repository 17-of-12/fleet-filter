#!/usr/bin/env bash
# tests/load/nftables_redirect_lab.sh - Bundle D4: prototype the nftables redirect path.
#
# Why this exists: Bundle D's question is whether a quarantined client should be diverted by
# Apache's mod_proxy (the shipped design, which costs one Apache worker per in-flight slow
# response) or by nftables (L3/L4 dnat, which costs Apache nothing). D1-D3 measured the Apache
# side. This script measures the nftables side on the same host without changing the shipped
# configuration permanently: everything it adds lives in one dedicated table that `revert`
# deletes, and the one host-wide sysctl it needs is captured and restored.
#
# The load-bearing detail this script exists to document: `dnat to 127.0.0.1` requires
# net.ipv4.conf.all.route_localnet=1. Without it the kernel drops a packet whose destination is
# in 127.0.0.0/8 when it arrives on a non-loopback interface, so the redirect silently does
# nothing and the measurement reads as "the client hung" rather than "the sysctl is off".
#
# Usage:
#   nftables_redirect_lab.sh status                     # show table, set, and the sysctl
#   nftables_redirect_lab.sh apply <client-ip> [listen] # create table+set, add <client-ip>
#   nftables_redirect_lab.sh measure [url]              # probe + capture Apache/responder state
#   nftables_redirect_lab.sh revert                     # delete the table, restore the sysctl
#
# `apply` then `revert` is the whole lifecycle; there is no other persistent state. Re-running
# `apply` is idempotent (the set element is re-added, the table is flushed rather than doubled).

set -euo pipefail

TABLE="fleet-filter-lab"
SET="quarantined"
DEFAULT_LISTEN="127.0.0.1:8081"
DEFAULT_URL="http://10.30.72.19/"
SYSCTL="net.ipv4.conf.all.route_localnet"

command -v nft >/dev/null || { echo "nft not found" >&2; exit 1; }

# current_value reads the sysctl so revert can restore exactly what was there, not a guess.
current_value() { sysctl -n "$SYSCTL" 2>/dev/null || echo 0; }

# snapshot_records the pre-existing nftables state. The guard against touching firewalld's
# tables is the point: this script only ever deletes $TABLE, and it refuses to run if a table
# it did not create is already named $TABLE (a hand-made table would be destroyed by `delete`).
precheck() {
    if nft list table ip "$TABLE" >/dev/null 2>&1; then
        if [ ! -f "/run/fleet-filter-lab.state" ]; then
            echo "table ip $TABLE exists but /run/fleet-filter-lab.state does not;" >&2
            echo "refusing to delete a table this script did not create." >&2
            exit 1
        fi
    fi
}

cmd_status() {
    echo "--- sysctl $SYSCTL = $(current_value)"
    if nft list table ip "$TABLE" 2>/dev/null; then
        :
    else
        echo "--- table ip $TABLE: absent"
    fi
}

cmd_apply() {
    local client="${1:-}"
    local listen="${2:-$DEFAULT_LISTEN}"
    [ -n "$client" ] || { echo "usage: $0 apply <client-ip> [listen]" >&2; exit 1; }
    precheck

    local prior
    # The recorded value wins over the live one. Re-applying after a partial run would otherwise
    # read back the 1 that the failed run set and record *that* as the original, permanently
    # losing the real baseline (0) - which is exactly how a lab sysctl becomes a permanent,
    # undocumented host change. The state file is the single source of truth for the baseline.
    if [ -f "/run/fleet-filter-lab.state" ]; then
        prior="$(sed -n 's/^route_localnet_prior=//p' /run/fleet-filter-lab.state)"
    else
        prior="$(current_value)"
    fi
    if [ "$prior" != "1" ]; then
        sysctl -w "${SYSCTL}=1" >/dev/null
    fi
    # The state file is also the only proof that the sysctl value belongs to us; without it a
    # second operator's `revert` would set route_localnet back to 0 while someone else still
    # relies on 1.
    printf 'route_localnet_prior=%s\ntable=%s\nlisten=%s\n' "$prior" "$TABLE" "$listen" \
        > "/run/fleet-filter-lab.state"

    nft delete table ip "$TABLE" 2>/dev/null || true
    nft add table ip "$TABLE"
    # Timeout on the set is the J1 requirement: an element ages out on its own, so a forgotten
    # lab entry cannot outlive the experiment it was added for.
    nft add set ip "$TABLE" "$SET" '{ type ipv4_addr ; timeout 1h ; }'
    nft add element ip "$TABLE" "$SET" "{ $client }"
    # Only dport 80 is redirected (the task's "HTTP only" scope) and only from addresses in the
    # set, so every other client of this host keeps being served by Apache exactly as before.
    nft add chain ip "$TABLE" prerouting '{ type nat hook prerouting priority dstnat ; }'
    nft add rule ip "$TABLE" prerouting "ip saddr @$SET tcp dport 80 dnat to $listen"
    nft list table ip "$TABLE"
}

cmd_revert() {
    [ -f "/run/fleet-filter-lab.state" ] || { echo "nothing to revert" >&2; exit 1; }
    local prior
    prior="$(sed -n 's/^route_localnet_prior=//p' /run/fleet-filter-lab.state)"
    nft delete table ip "$TABLE" 2>/dev/null || true
    sysctl -w "${SYSCTL}=${prior:-0}" >/dev/null
    rm -f /run/fleet-filter-lab.state
    echo "reverted: table ip $TABLE removed, $SYSCTL=$(current_value)"
}

# cmd_measure probes the URL and records the two things the comparison turns on: the latency the
# client experiences, and whether Apache holds a connection while that latency is being paid.
# A dnat'd request shows a connection on the responder's port and none on Apache's.
cmd_measure() {
    local url="${1:-$DEFAULT_URL}"
    local before after children
    before="$(date +%s)"
    local code time_total
    read -r code time_total < <(curl -s -o /dev/null -w '%{http_code} %{time_total}' \
        --max-time 30 "$url" 2>/dev/null || echo "000 0")
    after="$(date +%s)"
    echo "url=$url http=$code time=$time_total wall=$((after - before))s"
    echo "--- listeners holding connections"
    ss -Htn state established 2>/dev/null | awk '{print $3, $4}' | sort | uniq -c | sort -rn | head -8
    echo "--- httpd children and their fd counts"
    for pid in $(pgrep -f "httpd" 2>/dev/null | head -6); do
        printf "  pid=%s fds=%s cmd=%s\n" "$pid" \
            "$(ls /proc/$pid/fd 2>/dev/null | wc -l)" \
            "$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-40)"
    done
}

case "${1:-status}" in
    status) cmd_status ;;
    apply) shift; cmd_apply "$@" ;;
    revert) cmd_revert ;;
    measure) shift; cmd_measure "$@" ;;
    *) echo "unknown command: $1" >&2; exit 1 ;;
esac
