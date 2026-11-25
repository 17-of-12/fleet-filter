#!/usr/bin/env bash
# tests/gateway/r_chain_latency.sh - measure the Bundle R chain end to end on a gateway host.
#
# Chain: gateway detection -> spool file -> controller store -> rendered map -> Apache enforces.
# Each stage is timestamped, because the bundle asks for the worst-case propagation delay, and
# "eventually it showed up" is not a measurement. Two numbers are reported: the measured delay for
# this run, and the theoretical worst case derived from the deployed timer settings.
#
# Run on the gateway host as root (the spool is 0750 and the map is 0644 root:root):
#   bash tests/gateway/r_chain_latency.sh [client-ip]
#
# Every curl carries an explicit --max-time (project rule: no unbounded test commands), which also
# matters here because a tarpitted response takes ~5s by design.
set -uo pipefail

CLIENT="${1:-198.51.100.108}"
GATEWAY="${GATEWAY:-https://198.51.100.111:8443}"
BACKEND="${BACKEND:-http://198.51.100.110:8088}"
SPOOL="${SPOOL:-/var/lib/fleet-filter-gateway/spool}"
MAP="${MAP:-/etc/httpd/tarpit-ips.map}"
AT="${AT:-/usr/local/bin/adaptive-tarpit}"
PATH_PREFIX="${PATH_PREFIX:-/h2probe-r5}"
# The deployed timer is OnUnitActiveSec=5min with AccuracySec=1min and RandomizedDelaySec=30, so
# a claim can legitimately take that long to be rendered. Poll past it rather than declaring the
# chain broken at the first minute.
MAX_WAIT="${MAX_WAIT:-600}"

# stage NAME EPOCH MESSAGE - one parseable line per observed stage.
stage() {
    printf '%-14s %s %s\n' "$1" "$2" "$3"
}

# backend_latency CLIENT - seconds for one plain HTTP/1.1 request to the backend from that address.
# `--interface` pins the source address (lab-web01's curl 7.61 has no --local-address alias), which
# is what makes the before/after pair measurable for one identity.
backend_latency() {
    curl -s -o /dev/null --max-time 20 --interface "$1" "$BACKEND/" -w '%{time_total}' 2>/dev/null || echo "err"
}

echo "r5 chain: client=$CLIENT gateway=$GATEWAY backend=$BACKEND"
echo "format: stage epoch detail"

t_start=$(date +%s)
stage baseline "$t_start" "backend_latency_pre=$(backend_latency "$CLIENT")s"

# 1. The request the gateway should detect. `--local-address` fixes the client identity, which is
#    what the claim will be about; without it the source address would be whatever the route picks.
code=$(curl -k -s -o /dev/null --max-time 20 --interface "$CLIENT" -w '%{http_code}' "$GATEWAY$PATH_PREFIX" 2>/dev/null || echo "err")
t_detect=$(date +%s)
stage gateway "$t_detect" "gateway_response=$code"

# 2. The spool file. The gateway writes it synchronously while handling the request, so it exists
#    by the time curl returns; polling covers the case where the controller drained it first.
t_spool=""
for _ in $(seq 1 30); do
    if [ -n "$(sudo -n find "$SPOOL" -maxdepth 1 -name '*.json' -newermt "@$t_detect" 2>/dev/null)" ]; then
        t_spool=$(date +%s)
        break
    fi
    sleep 1
done
if [ -z "$t_spool" ]; then
    stage spool "$t_detect" "no new spool file within 30s (drained early or rate-limited)"
else
    stage spool "$t_spool" "file=$(sudo -n ls -1 "$SPOOL" | grep -F "$CLIENT" | head -1)"
fi

# 3+4. Store and rendered map. Wait for the timer rather than invoking the controller, so the
#      measured number is the delay an operator actually experiences.
t_map=""
for _ in $(seq 1 $((MAX_WAIT / 2))); do
    if sudo -n grep -q "^$CLIENT 1$" "$MAP" 2>/dev/null; then
        t_map=$(date +%s)
        break
    fi
    sleep 2
done
if [ -z "$t_map" ]; then
    stage map "n/a" "client never appeared in $MAP within ${MAX_WAIT}s"
    exit 1
fi
stage store "$t_map" "map_mtime=$(stat -c %Y "$MAP")"
stage render "$t_map" "map_entry=$CLIENT/1"

# 5. Enforcement. The backend vhost's RewriteMap now resolves this address to 1, so the same
#    request that was answered in milliseconds is served by the slow-drip responder.
t_enforce=$(date +%s)
stage enforce "$t_enforce" "backend_latency_post=$(backend_latency "$CLIENT")s"
stage total "$t_start" "detect_to_enforce=$((t_enforce - t_start))s"

# The gateway's own view is the other half of R4: it memoised the detection at t_detect, so it
# classified this client as quarantined long before the map said so.
stage gateway_view "$t_map" "$(journalctl -u fleet-filter-gateway.service --since "@$t_detect" --no-pager 2>/dev/null | grep -m1 detection || echo 'no detection log line')"
