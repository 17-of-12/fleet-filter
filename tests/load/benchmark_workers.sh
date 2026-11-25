#!/usr/bin/env bash
# D1/D2 - Apache worker economics: cost of simultaneous slow responses.
#
# The brief's question 13.6 is "how many concurrent tarpitted responses can this host hold before
# production latency, worker availability, or 5xx rate degrades". Two answers exist and only one is
# correct on any given host, because two independent pools bound it:
#
#   * Apache's worker/fd pool - every proxied slow response holds a connection to the backend.
#   * The responder's handler pool - `--max-threads` / `--per-ip-max` (PT-07) cap how many drips
#     one process will run, and answer 503 instead of queuing when the pool is full.
#
# Whichever pool binds first sets the real ceiling, so this harness measures both on every level
# instead of guessing. Concurrency is spread across real quarantined addresses because `per_ip_max`
# means one address can never hold more than 4 drips; driving 32 concurrent requests from a single
# address measures the per-IP cap, not the pool.
#
# A control request from an allowlisted source is issued at every level: the number that matters is
# not how slow the tarpitted clients get, it is whether a *normal* user notices.
#
# Usage: bash benchmark_workers.sh [levels_csv]     default: 1 2 4 8 16 24 32 40 48 64
set -uo pipefail

MAP=/etc/httpd/tarpit-ips.map
ALLOWLIST=/etc/adaptive-tarpit/allowlist
TARGET="${BENCH_TARGET:-http://198.51.100.110:8088}"
PATH_UNDER_TEST=/ai.html
MAX_SOURCES="${BENCH_MAX_SOURCES:-8}"
LEVELS="${1:-1 2 4 8 16 24 32 40 48 64}"
WORKDIR=$(mktemp -d /tmp/bench-workers.XXXXXX)
trap 'rm -rf "$WORKDIR"' EXIT

# ---------------------------------------------------------------- source discovery
quarantined_sources() { # addresses the live map marks as value 1 (tarpitted)
    awk 'NR>2 && $2==1 {print $1}' "$MAP" 2>/dev/null | head -"$MAX_SOURCES"
}

allowlisted_source() { # an address the map marks as value 0, for the control request
    awk 'NR>2 && $2==0 {print $1; exit}' "$MAP" 2>/dev/null
}

# ---------------------------------------------------------------- cost sampling
apache_cost() { # "children established_connections max_fds_in_a_child"
    local children fds max=0 n
    children=$(pgrep -c httpd 2>/dev/null || echo 0)
    for pid in $(pgrep httpd 2>/dev/null); do
        n=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
        [[ "$n" -gt "$max" ]] && max="$n"
    done
    fds=$(ss -Htn state established 2>/dev/null | grep -c ':8088' || echo 0)
    printf '%s %s %s' "$children" "$fds" "$max"
}

responder_cost() { # "threads rss_kb open_fds" for the running responder, 0s if not running
    local pid
    pid=$(systemctl show -p MainPID --value tarpit-test.service 2>/dev/null)
    [[ -z "$pid" || "$pid" == "0" ]] && { printf '0 0 0'; return 0; }
    local threads rss fds
    threads=$(awk '/^Threads:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
    rss=$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
    fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
    printf '%s %s %s' "${threads:-0}" "${rss:-0}" "$fds"
}

# ---------------------------------------------------------------- one level
run_level() { # run_level <concurrency> -> prints a markdown row
    local n="$1" srcs=() row i src
    mapfile -t srcs < <(quarantined_sources)
    local per_ip=4
    local capacity=$(( ${#srcs[@]} * per_ip ))
    if [[ "$n" -gt "$capacity" ]]; then
        printf '| %s | skipped: %s quarantined addresses x per_ip_max %s = %s | | | | | |\n' \
            "$n" "${#srcs[@]}" "$per_ip" "$capacity"
        return 0
    fi

    # Fire N requests, round-robined across the quarantined addresses, all in background.
    : > "$WORKDIR/results.$n"
    for ((i = 0; i < n; i++)); do
        src="${srcs[$((i % ${#srcs[@]}))]}"
        curl -s -o /dev/null --interface "$src" --max-time 30 \
            -w '%{http_code} %{time_total}\n' "$TARGET$PATH_UNDER_TEST" \
            >> "$WORKDIR/results.$n" 2>/dev/null &
    done

    # Sample the two pools while the drips are in flight (they take ~5 s, so there is time).
    sleep 1
    local acontrol aresult
    aresult=$(allowlisted_source)
    local control="n/a"
    [[ -n "$aresult" ]] && control=$(curl -s -o /dev/null --interface "$aresult" --max-time 30 \
        -w '%{http_code} %{time_total}' "$TARGET$PATH_UNDER_TEST" 2>/dev/null || echo "000 0")
    local acost rcost
    acost=$(apache_cost)
    rcost=$(responder_cost)

    wait
    local codes ok slow err
    codes=$(awk '{print $1}' "$WORKDIR/results.$n" | sort | uniq -c | tr '\n' ' ' | sed 's/^ *//')
    # `grep -c` prints the count AND exits non-zero on a zero count, so `|| echo 0` would
    # emit a second line ("0\n0") for a clean run. Swallow the status, keep the printed count.
    ok=$(grep -c '^200' "$WORKDIR/results.$n" 2>/dev/null || true)
    err=$(grep -cE '^(503|000)' "$WORKDIR/results.$n" 2>/dev/null || true)
    slow=$(awk '$1==200 {s+=$2; c++} END{if (c) printf "%.2f", s/c; else printf "n/a"}' "$WORKDIR/results.$n")

    printf '| %s | %s | %s | %s | %s | %s | %s |\n' \
        "$n" "$codes" "$ok" "$err" "$slow" "$control" "apache: $acost | responder: $rcost"
}

main() {
    echo "# D1/D2 worker economics - $(hostname -f 2>/dev/null || hostname) - $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "target \`$TARGET$PATH_UNDER_TEST\` · map \`$MAP\` · responder flags from \`systemd/tarpit-test.service\`:"
    echo "\`--max-threads 32 --per-ip-max 4 --chunk-size 3 --chunk-delay 0.05 --max-drip 5\`"
    echo
    local qs; qs=$(quarantined_sources | wc -l)
    echo "quarantined addresses available for this run: **$qs** (cap \`BENCH_MAX_SOURCES=$MAX_SOURCES\`)"
    echo
    printf '| concurrency | status codes | 200 | 503/000 | mean drip (s) | control (allowlisted) | pool cost |\n'
    printf '|---|---|---|---|---|---|---|\n'
    for level in $LEVELS; do
        run_level "$level"
    done
}

main "$@"
