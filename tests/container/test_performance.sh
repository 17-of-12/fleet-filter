#!/usr/bin/env bash
# tests/container/test_performance.sh - Bundle W5: native vs containerised Apache on identical traffic.
#
# W5 requires thresholds taken from measured baselines rather than invented numbers, so this script
# produces the baseline: the same request, repeated, against the three listeners that exist on the
# canary host - the native :80 vhost, the Stage 2 backend vhost on 198.51.100.110:8088, and the
# containerised vhost on 127.0.0.1:18080. Sequential latency answers "did containerisation make the
# request slower"; a small concurrent burst answers "does it fall over sooner".
#
# The source address is checked against the live quarantine map before anything is measured. A
# quarantined client is served a 5 s slow-drip, and a benchmark run against a quarantined address
# once cost 26 minutes for a 300-request suite; the check is the reason this script is safe to re-run.
#
# Usage: tests/container/test_performance.sh [host] [ssh-user] [requests]
set -uo pipefail

HOST="${1:-lab-web01.lab}"
USER_SSH="${2:-agent}"
N="${3:-150}"
MAP="/etc/httpd/tarpit-ips.map"
SRC="127.0.0.1"

rsh() { timeout 300 ssh -o BatchMode=yes -o ConnectTimeout=10 "$USER_SSH@$HOST" "sudo -n bash -s" <<<"$1" 2>&1; }

echo "W5 performance baseline on $HOST ($N sequential requests per listener, plus a 10-request burst)"

# --- refuse to measure a quarantined source --------------------------------------------------------
state="$(rsh "awk -v ip=$SRC '\$1==ip{print \$2}' $MAP | head -1")"
if [[ "$state" == "1" || "$state" == "2" ]]; then
    echo "$SRC is mapped as state $state in $MAP; a slow-drip response would dominate the numbers." >&2
    echo "Revoke the lease or pass a different source before benchmarking." >&2
    exit 1
fi

# --- sequential latency per listener -----------------------------------------------------------------
declare -A OUT
for label in "native-http80:http://127.0.0.1/ai.html" \
             "gateway-backend-8088:http://198.51.100.110:8088/ai.html" \
             "canary-container-18080:http://127.0.0.1:18080/ai.html"; do
    name="${label%%:*}"; url="${label#*:}"
    extra=""
    [[ "$name" == "native-http80" ]] && extra="-H \"Host: lab-web01.lab\""
    raw="$(rsh "for i in \$(seq 1 $N); do curl -s -o /dev/null -w '%{time_total}\\n' --max-time 20 $extra '$url'; done")"
    OUT["$name"]="$(printf '%s' "$raw" | tr -d '\r' | grep -E '^[0-9.]+$' | python3 -c '
import sys
v = sorted(float(x) for x in sys.stdin.read().split())
if not v:
    print("no samples"); raise SystemExit
def pct(p):
    return v[min(len(v) - 1, int(round(p * (len(v) - 1))))]
print(f"n={len(v)} min={v[0]*1000:.2f}ms p50={pct(0.5)*1000:.2f}ms p95={pct(0.95)*1000:.2f}ms max={v[-1]*1000:.2f}ms")
')"
    printf "%-24s %s\n" "$name" "${OUT[$name]}"
done

# --- concurrent burst per listener -------------------------------------------------------------------
echo
echo "burst (10 parallel requests, wall clock):"
for label in "native-http80:http://127.0.0.1/ai.html" \
             "gateway-backend-8088:http://198.51.100.110:8088/ai.html" \
             "canary-container-18080:http://127.0.0.1:18080/ai.html"; do
    name="${label%%:*}"; url="${label#*:}"
    extra=""
    [[ "$name" == "native-http80" ]] && extra="-H \"Host: lab-web01.lab\""
    # nanosecond clock diffed as an integer and reported in ms; bash cannot do float arithmetic,
    # which is why the earlier `date +%s.%N` form needs the .N folded into the same integer.
    wall="$(rsh "s=\$(date +%s%N); for i in \$(seq 1 10); do curl -s -o /dev/null --max-time 20 $extra '$url' & done; wait; e=\$(date +%s%N); echo \$(( (e-s)/1000000 ))" | tail -1)"
    printf "%-24s %sms\n" "$name" "$wall"
done
