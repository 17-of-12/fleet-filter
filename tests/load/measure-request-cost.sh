#!/bin/sh
# Measure Apache request cost and response shape for a set of paths.
#
# Purpose
# -------
# Two questions get answered by one script, because they need the same measurement:
#   * Bundle L2 - what does adding Tier 1 signature matching cost per request?
#   * the code review's missing `tests/load` - there was no way to answer "is this
#     safe under load" with a number instead of an opinion.
#
# Both questions are about *deltas*, so the script's contract is "same arguments in,
# comparable JSON out". A baseline run and a post-change run are diffable because the
# measurement method is identical, not because the two runs happened to look similar.
#
# What is measured and why
# ------------------------
#   time_total     full request time as seen by the client (the number that matters for
#                  both "did the tarpit delay this" and "did the regex slow down normal
#                  traffic")
#   http_code      a rule that changes routing usually changes the status; timing alone
#                  can hide a regression (a fast 500 looks like a fast 200)
#   size_download  catches the subtler case where the body changed but the status did not
#   httpd CPU      wall-clock latency cannot see server-side cost when the response is
#                  dominated by network or by an intentional drip, so the process CPU
#                  counters are sampled before and after and reported as a delta
#
# `--interface` is required rather than optional: the tarpit's behaviour is a function of
# the *source address* (RewriteMap), so measuring from an address that happens to be
# quarantined silently measures the tarpit instead of the vhost.

set -eu

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-80}"
SRC=""
PATHS="/"
COUNT=1
LABEL="unlabelled"
OUT=""
MAX_TIME="${MAX_TIME:-10}"
MAP="${MAP:-}"
EXPECT_MAPPED=0
CONFIGS=""

usage() {
    echo "usage: $0 --src-ip ADDR [--host H] [--port P] [--paths /a,/b] [--count N] [--label L] [--out FILE] [--max-time S] [--map FILE] [--expect-mapped] [--config NAME=PATH ...]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --host)    HOST="$2"; shift 2 ;;
        --port)    PORT="$2"; shift 2 ;;
        --src-ip)  SRC="$2"; shift 2 ;;
        --paths)   PATHS="$2"; shift 2 ;;
        --count)   COUNT="$2"; shift 2 ;;
        --label)   LABEL="$2"; shift 2 ;;
        --out)     OUT="$2"; shift 2 ;;
        --max-time) MAX_TIME="$2"; shift 2 ;;
        --map)     MAP="$2"; shift 2 ;;
        --expect-mapped) EXPECT_MAPPED=1; shift ;;
        --config)  CONFIGS="$CONFIGS $2"; shift 2 ;;
        *)         usage ;;
    esac
done

[ -n "$SRC" ] || usage

# Preflight - refuse to measure a quarantined source address when the caller meant to
# measure a normal client.
#
# Why this exists: the tarpit's latency is a property of the *source address*, so reusing an
# address that a previous run got quarantined measures the drip, not the vhost. The first
# time this happened a 300-request run took 26 minutes and every number in it was about the
# wrong thing. Failing here costs one grep.
if [ -n "$MAP" ] && [ -r "$MAP" ]; then
    if awk -v ip="$SRC" '$1 == ip && $2 != "0" { found = 1 } END { exit !found }' "$MAP"; then
        if [ "$EXPECT_MAPPED" -eq 1 ]; then
            echo "note: $SRC is present in $MAP and the caller expects that" >&2
        else
            echo "error: $SRC is quarantined in $MAP; this run would measure the tarpit." >&2
            echo "       pass --expect-mapped to measure it anyway, or use a fresh address." >&2
            exit 3
        fi
    fi
fi

# Config fingerprint - md5 of every file the label claims is in effect.
#
# A run is only comparable to another run if the configuration really is what the label says.
# One measurement set was written up as "tier1-enabled" while the vhost still had the
# generated include commented out, and nothing in the output could prove it. Recording the
# hashes makes a mislabelled run detectable after the fact, and `--out` files from two
# different configs can no longer look identical.
CONFIG_JSON=""
for spec in $CONFIGS; do
    name="${spec%%=*}"; path="${spec#*=}"
    hash="$(md5sum "$path" 2>/dev/null | awk '{print $1}')"
    [ -n "$hash" ] || hash="unreadable"
    CONFIG_JSON="${CONFIG_JSON:+$CONFIG_JSON, }\"$name\": \"$hash\""
done

# Budget - the run is bounded by construction rather than by hope.
#
# A drip response takes seconds, so `count` sequential requests cost roughly
# count * per-request-time. Each request now carries its own `timeout` (see one_path), which
# bounds the whole loop at COUNT * MAX_TIME; the previous version relied on curl's --max-time
# alone and one socket that never returned held a 300-request run open for 26 minutes.

# httpd_cpu_ticks - sum utime+stime across every httpd process.
#
# Summing all processes (parent + children) rather than just the parent: with the event MPM
# the work happens in the children, and the parent's counters stay nearly flat, so reading
# only the parent would report ~0 ticks for any amount of served traffic.
httpd_cpu_ticks() {
    ps -C httpd -o utime=,stime= 2>/dev/null \
        | awk '{ split($1,a,":"); split($2,b,":"); t+=a[1]*60+a[2]+b[1]*60+b[2] } END { print t+0 }'
}

CPU_BEFORE="$(httpd_cpu_ticks)"
START_NS="$(date +%s%N 2>/dev/null || echo 0)"

# one_path - issue `count` requests for one path and emit one JSON object.
#
# curl's -w format is used instead of timing in shell because `date` resolution and the
# fork/exec cost of curl itself would dominate a 2 ms local request. Each request also runs
# under `timeout`, because curl's own --max-time has been observed not to fire on a socket
# whose peer disappeared during an httpd reload.
one_path() {
    path="$1"
    i=0
    sum_ms=0
    max_ms=0
    codes=""
    sizes=""
    while [ "$i" -lt "$COUNT" ]; do
        line="$(timeout -s TERM "$MAX_TIME" curl -o /dev/null -s --max-time "$MAX_TIME" \
                    --interface "$SRC" \
                    -w '%{http_code} %{time_total} %{size_download}' \
                    "http://${HOST}:${PORT}${path}" 2>/dev/null || echo "000 0 0")"
        code="$(printf '%s' "$line" | awk '{print $1}')"
        t="$(printf '%s' "$line" | awk '{print $2}')"
        size="$(printf '%s' "$line" | awk '{print $3}')"
        ms="$(awk -v s="$t" 'BEGIN { printf "%.0f", s*1000 }')"
        sum_ms=$((sum_ms + ms))
        [ "$ms" -gt "$max_ms" ] && max_ms="$ms"
        codes="$codes $code"
        sizes="$sizes $size"
        i=$((i + 1))
    done
    avg="$(awk -v s="$sum_ms" -v n="$COUNT" 'BEGIN { printf "%.1f", s/n }')"
    # Unique sizes, not the first one: a rule that changes the body without changing the
    # status is exactly the regression this harness is meant to catch, and reporting only
    # the first response would hide a body that alternates.
    size_set="$(printf '%s' "$sizes" | tr ' ' '\n' | awk 'NF && !seen[$0]++' | tr '\n' ' ' | sed 's/ $//')"
    printf '  {"path": "%s", "requests": %s, "avg_ms": %s, "max_ms": %s, "codes": "%s", "sizes": "%s"}' \
        "$path" "$COUNT" "$avg" "$max_ms" \
        "$(printf '%s' "$codes" | sed 's/^ //')" \
        "$size_set"
}

# The request loop must run *between* the two CPU samples, so its output is buffered to a
# temp file and the JSON is assembled afterwards. An earlier version emitted the header
# before running the loop, which fixed END_NS/CPU_AFTER at a point where no request had been
# made and reported a permanent 0 tick delta and a ~2 ms wall clock for 200 requests.
BODY="$(mktemp)"
trap 'rm -f "$BODY"' EXIT
{
    first=1
    oldIFS="$IFS"; IFS=','
    for p in $PATHS; do
        [ "$first" -eq 1 ] || printf ',\n'
        first=0
        one_path "$p"
    done
    IFS="$oldIFS"
} > "$BODY"

END_NS="$(date +%s%N 2>/dev/null || echo 0)"
CPU_AFTER="$(httpd_cpu_ticks)"

{
    printf '{\n'
    printf '  "label": "%s",\n' "$LABEL"
    printf '  "generated_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "target": "http://%s:%s",\n' "$HOST" "$PORT"
    printf '  "source_address": "%s",\n' "$SRC"
    printf '  "source_quarantined_at_measure_time": %s,\n' "$([ -n "$MAP" ] && [ -r "$MAP" ] && awk -v ip="$SRC" 'BEGIN{f="false"} $1==ip && $2!="0"{f="true"} END{print f}' || echo null)"
    printf '  "config_md5": {%s},\n' "$CONFIG_JSON"
    printf '  "wall_clock_ms": %s,\n' "$(awk -v a="$START_NS" -v b="$END_NS" 'BEGIN { printf "%.0f", (b-a)/1000000 }')"
    printf '  "httpd_cpu_ticks_before": %s,\n' "$CPU_BEFORE"
    printf '  "httpd_cpu_ticks_after": %s,\n' "$CPU_AFTER"
    printf '  "httpd_cpu_ticks_delta": %s,\n' "$(awk -v a="$CPU_BEFORE" -v b="$CPU_AFTER" 'BEGIN { printf "%.0f", b-a }')"
    printf '  "results": [\n'
    cat "$BODY"
    printf '\n  ]\n}\n'
} > "${OUT:-/dev/stdout}"

[ -n "$OUT" ] && cat "$OUT" || true
