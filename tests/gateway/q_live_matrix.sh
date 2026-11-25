#!/usr/bin/env bash
# tests/gateway/q_live_matrix.sh - run the Bundle Q live scenarios against a local frameprobe.
#
# Each scenario starts a frameprobe listener (one connection, then it exits), drives it with the
# h2probe HTTP/2 client, and captures the listener's own report. The pair of numbers that answers
# Q3 is `served=` from the listener versus what the client managed to get: served=0 with a refusal
# means the request never reached hyper's handler, which is the difference between telemetry and
# enforcement.
#
# usage: q_live_matrix.sh <frameprobe-binary> <h2probe-binary> <cert> <key> [sni]

set -u
FP="${1:-/home/agent/frameprobe}"
H2="${2:-/tmp/h2probe}"
CRT="${3:-/tmp/gw-test.crt}"
KEY="${4:-/tmp/gw-test.key}"
SNI="${5:-lab-web01.lab}"
PORT="${PORT:-18443}"

# scenario LABEL H2PATH [extra frameprobe rules...]
#
# Starts the listener on a fresh port, waits for it to bind, runs the client with an explicit
# timeout (project rule: no unbounded test commands), then prints the listener's report.
scenario() {
    local label="$1"
    local path="$2"
    shift 2
    local port="$PORT"
    local out="/tmp/q-$label.log"
    ( timeout 25 "$FP" --listen "127.0.0.1:$port" --tls-cert "$CRT" --tls-key "$KEY" \
        --connections 1 --max-seconds 20 --dump-frames "$@" >"$out" 2>&1 ) &
    local job=$!
    # Give the listener a moment to bind; a client that connects too early gets ECONNREFUSED and
    # the scenario would report a false failure.
    sleep 1
    local client
    client="$(timeout 20 "$H2" --url "https://127.0.0.1:$port$path" --streams 4 --insecure --sni "$SNI" 2>&1 | head -6)"
    wait "$job" 2>/dev/null
    echo "=== $label (path=$path rules=$*) ==="
    echo "--- listener ---"
    sed -n '1,12p' "$out"
    echo "--- client ---"
    echo "$client"
    echo
}

# Everything a hyper client can legitimately send on this connection.
ALL="SETTINGS,HEADERS,DATA,WINDOW_UPDATE,PRIORITY,RST_STREAM,CONTINUATION,PING,PUSH_PROMISE,GOAWAY"

# A: telemetry baseline - observe only, nothing should change for the client.
scenario A-observe /index.html --rule observe
# B: enforce with a permissive policy - enforcement must be transparent when nothing is violated.
#    The first version of this scenario allowed only SETTINGS,HEADERS,DATA and therefore refused a
#    legal WINDOW_UPDATE; a policy that does not name every type the peer sends is a policy that
#    breaks real clients, and only the live run exposed that.
scenario B-enforce-permissive /index.html --rule enforce --rule "allow=$ALL"
# C: refuse HEADERS specifically - every other frame is allowed, so the abort can only come from
#    the frame that carries the request.
scenario C-enforce-no-headers /index.html --rule enforce --rule "allow=SETTINGS,WINDOW_UPDATE,DATA,PRIORITY,RST_STREAM,CONTINUATION,PING,PUSH_PROMISE,GOAWAY"
# D: enforce on a header *value* (needs HPACK): the CVE-2026-119618 PoC path pattern.
scenario D-enforce-path-hit /h2probe-12345 --rule enforce --rule path-contains=/h2probe-
# E: same policy, non-matching path - the false-positive control.
scenario E-enforce-path-miss /index.html --rule enforce --rule path-contains=/h2probe-
