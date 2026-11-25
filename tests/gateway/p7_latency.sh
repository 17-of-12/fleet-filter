#!/usr/bin/env bash
# tests/gateway/p7_latency.sh - P7: latency comparison, direct Apache vs gateway(h1->h1) vs
# gateway(h2->h1), reported as p50/p95/p99 from raw per-request samples.
#
# Every sample is a fresh curl invocation with no connection reuse, so the TLS handshake on the
# gateway paths is included in the number rather than hidden by pooling. That is the honest
# comparison for a front end: a client that reconnects pays the handshake, and the reader needs to
# see what the gateway costs, not what a warm pool hides.
#
# Usage: p7_latency.sh [N] [backend_url] [gateway_url]

set -u
N="${1:-60}"
BACKEND="${2:-http://198.51.100.110:8088}"
GATEWAY="${3:-https://198.51.100.111:8443}"
PATH_TO_TEST="${PATH_TO_TEST:-/googleapi/index.html}"

# sample LABEL [curl args...] -> one line of percentiles
#
# Percentiles come from awk rather than python so the script runs on a host whose only interpreters
# are 3.6 and 3.9; the previous version piped into `python -` with a heredoc, which replaced stdin
# with the program text and produced zero samples.
sample() {
    local label="$1"
    shift
    local file
    file="$(mktemp)"
    local _i
    for _i in $(seq 1 "$N"); do
        curl -k -sS -o /dev/null --max-time 15 -w '%{time_total}\n' "$@" >>"$file" 2>/dev/null || true
    done
    sort -n "$file" | awk -v label="$label" '
        { v[NR] = $1 }
        END {
            if (NR == 0) { printf "%-14s no samples\n", label; exit }
            # Nearest-rank percentiles on the sorted sample set.
            p50 = v[int(0.50 * (NR - 1)) + 1]
            p95 = v[int(0.95 * (NR - 1)) + 1]
            p99 = v[int(0.99 * (NR - 1)) + 1]
            printf "%-14s n=%3d p50=%7.1fms p95=%7.1fms p99=%7.1fms min=%7.1fms max=%7.1fms\n",
                   label, NR, p50 * 1000, p95 * 1000, p99 * 1000, v[1] * 1000, v[NR] * 1000
        }
    '
    rm -f "$file"
}

echo "target path: $PATH_TO_TEST   samples per path: $N   (fresh connection per sample)"
sample "direct-h1" --http1.1 "${BACKEND}${PATH_TO_TEST}"
sample "gateway-h1" --http1.1 "${GATEWAY}${PATH_TO_TEST}"
sample "gateway-h2" --http2 "${GATEWAY}${PATH_TO_TEST}"
