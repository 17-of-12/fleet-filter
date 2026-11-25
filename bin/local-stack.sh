#!/usr/bin/env bash
# local-stack.sh - run the whole Fleet Filter stack on one loopback box, for development.
#
# Purpose
# -------
# The deployed system is split across two fleet hosts (build01 = control node, lab-web01 = the
# served site), and nothing on either host can be exercised without touching it over SSH. This
# script stands the same three processes up on loopback so a change can be seen working before it
# is anywhere near a fleet host:
#
#   controller store   var/state.db          (renders var/tarpit-ips.map)
#   real app          127.0.0.1:9000         python3 -m http.server, stands in for the site
#   gateway           127.0.0.1:3001         gateway binary, classifies from the rendered map
#   responder         127.0.0.1:8081         tarpit/server/server.py + the I1 catalogue
#   console           127.0.0.1:8188         web/app.py over var/cache.db
#
# Topology matters here and it is the deployed one: the gateway sits in front of the real site and
# answers a quarantined client itself (`--on-quarantined inline`), so the slow path is the gateway's
# own bounded drip. The Python responder is started too, and `verify` measures it directly, because
# it is the Stage 1 path a host without the gateway runs.
#
# It is a development harness, not a deployment: no Apache, no nftables, no Wazuh, TLS off, and
# every path is inside var/ so nothing here can collide with a real install. The gateway listens on
# plain HTTP because the thing under test is the map lookup and the slow drip, not the TLS layer.
#
# Design notes
# ------------
# * Only the responder and the console run from source under .venv; the gateway runs the native
#   release binary. A native build is explicitly not shippable (it links the host glibc and cannot
#   run on the EL8 fleet) - `bin/build-gateway.sh` in the container stays the artifact path. Using
#   it here is the point: fast local feedback without a podman build.
# * `up` is idempotent per port: a process already listening is left alone and reported, so a
#   second run reports the stack instead of creating a duplicate. Every step prints one line and
#   exits non-zero on failure rather than half-starting.
# * `verify` is the acceptance test for the harness: it asserts the property the project exists to
#   provide - an unmapped source is answered fast, a mapped source is answered slowly, and both
#   get a real body - by measuring wall time, because a 200 in 4 ms is exactly what a broken map
#   lookup returns (the 2026-11-13 silent regression).
# * Paths are relative to the repository, so this works from a checkout anywhere and cannot write
#   outside the tree.
#
# Usage
# -----
#   bin/local-stack.sh up        # build if needed, start everything, print the URLs
#   bin/local-stack.sh down      # stop everything it started
#   bin/local-stack.sh status    # pid, port and health of each process
#   bin/local-stack.sh verify    # measure mapped vs unmapped latency end to end
#   bin/local-stack.sh sync      # refresh the console cache from the registry
#   bin/local-stack.sh logs [n]  # tail the four logs

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${VENV:-${REPO_ROOT}/.venv}"
VAR="${VAR:-${REPO_ROOT}/var}"
RUN_DIR="${VAR}/run"
LOG_DIR="${VAR}/log"
CACHE="${VAR}/cache.db"
STATE_DB="${VAR}/state.db"
MAP="${VAR}/tarpit-ips.map"
AUDIT_LOG="${VAR}/audit.jsonl"
BYPASS_FILE="${VAR}/bypass.json"
SPOOL="${VAR}/spool"
RESPONSES="${VAR}/tarpit/responses"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/fleet-filter-gateway/target}"
GATEWAY_BIN="${GATEWAY_BIN:-${CARGO_TARGET_DIR}/release/fleet-filter-gateway}"
CONTROLLER="${REPO_ROOT}/controller/adaptive-tarpit.py"

APP_PORT="${APP_PORT:-9000}"
RESPONDER_PORT="${RESPONDER_PORT:-8081}"
GATEWAY_PORT="${GATEWAY_PORT:-3001}"
CONSOLE_PORT="${CONSOLE_PORT:-8188}"

# One line per action, with the reason attached when it fails.
say() { printf '%-9s %s\n' "$1" "$2"; }
die() { printf '%-9s %s\n' "error" "$1" >&2; exit 1; }

# A port is "ours" when something is already listening on it; `up` then reports rather than
# duplicating, and `down` only kills what this script recorded.
port_open() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && exec 3<&- && return 0 || return 1
}

prepare_dirs() {
    mkdir -p "${RUN_DIR}" "${LOG_DIR}" "${SPOOL}" "${RESPONSES}" "${VAR}/www"
}

# Start one process with a pidfile and a log, after refusing to start a second copy.
start_proc() {
    local name="$1" port="$2"; shift 2
    local pidfile="${RUN_DIR}/${name}.pid"
    if [ -f "${pidfile}" ] && kill -0 "$(cat "${pidfile}")" 2>/dev/null; then
        say "running" "${name} pid=$(cat "${pidfile}") port=${port}"
        return 0
    fi
    if port_open "${port}"; then
        say "in use" "${name} port=${port} is already listening (not started by this script)"
        return 0
    fi
    nohup "$@" >"${LOG_DIR}/${name}.log" 2>&1 &
    echo $! >"${pidfile}"
    local waited=0
    while [ ${waited} -lt 100 ]; do
        port_open "${port}" && { say "started" "${name} pid=$(cat "${pidfile}") port=${port}"; return 0; }
        kill -0 "$(cat "${pidfile}")" 2>/dev/null || { tail -5 "${LOG_DIR}/${name}.log" >&2; die "${name} exited during startup (see ${LOG_DIR}/${name}.log)"; }
        sleep 0.1
        waited=$((waited + 1))
    done
    tail -5 "${LOG_DIR}/${name}.log" >&2
    die "${name} did not bind port ${port} within 10s"
}

build_gateway() {
    # Rebuild when the binary is missing *or older than the sources*. Using a stale release binary
    # while the tree has moved is how a shape fix appears not to work: the stack kept serving the
    # pre-2026-11-24 sleep-then-Full answer from ~/.cache while the source dripped.
    local stale=""
    if [ -x "${GATEWAY_BIN}" ] && [ -n "$(find "${REPO_ROOT}/gateway/src" -newer "${GATEWAY_BIN}" -print -quit 2>/dev/null)" ]; then
        stale=" (source newer than binary)"
    fi
    if [ -x "${GATEWAY_BIN}" ] && [ -z "${stale}" ]; then
        say "gateway" "using ${GATEWAY_BIN} ($("${GATEWAY_BIN}" --version 2>/dev/null || echo unknown))"
        return 0
    fi
    [ -n "${stale}" ] && say "rebuild" "${GATEWAY_BIN}${stale}"
    command -v cargo >/dev/null 2>&1 || die "cargo not found; install the 1.92.0 toolchain (SKILL.md build environment)"
    say "building" "gateway release binary (native, dev only)"
    ( cd "${REPO_ROOT}/gateway" && CARGO_TARGET_DIR="${CARGO_TARGET_DIR}" cargo build --release >/dev/null ) \
        || die "cargo build --release failed"
    [ -x "${GATEWAY_BIN}" ] || die "build produced no binary at ${GATEWAY_BIN}"
    say "built" "${GATEWAY_BIN}"
}

cmd_up() {
    [ -x "${VENV}/bin/python" ] || die "no .venv; run: python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt"
    prepare_dirs
    build_gateway
    # The map must exist before the gateway starts: a missing map is a fallback decision, and the
    # harness should exercise the normal path instead. An empty render is the honest starting state.
    if [ ! -f "${MAP}" ]; then
        "${VENV}/bin/python" "${CONTROLLER}" --db "${STATE_DB}" --map "${MAP}" \
            --audit-log "${AUDIT_LOG}" --bypass-file "${BYPASS_FILE}" \
            expire --render --allow-empty >/dev/null 2>&1 \
            || die "controller could not create ${MAP}"
        say "map" "created empty ${MAP}"
    fi
    if [ ! -f "${VAR}/www/index.html" ]; then
        printf '<!doctype html><title>site</title><h1>the real site</h1>\n' >"${VAR}/www/index.html"
        say "app" "created ${VAR}/www/index.html"
    fi
    start_proc app "${APP_PORT}" python3 -m http.server "${APP_PORT}" --bind 127.0.0.1 \
        --directory "${VAR}/www"
    start_proc gateway "${GATEWAY_PORT}" "${GATEWAY_BIN}" \
        --bind "127.0.0.1:${GATEWAY_PORT}" --backend "http://127.0.0.1:${APP_PORT}" \
        --map "${MAP}" --map-ttl 2 --spool "${SPOOL}" --on-quarantined inline
    start_proc responder "${RESPONDER_PORT}" "${VENV}/bin/python" \
        "${REPO_ROOT}/tarpit/server/server.py" \
        --bind 127.0.0.1 --port "${RESPONDER_PORT}" \
        --profiles "${REPO_ROOT}/tarpit/profiles/catalogue.yaml" \
        --responses-dir "${RESPONSES}" --advertise local
    start_proc console "${CONSOLE_PORT}" "${VENV}/bin/python" \
        "${REPO_ROOT}/web/app.py" --db "${CACHE}" --registry "${REPO_ROOT}/web/installs.yaml" \
        --port "${CONSOLE_PORT}"
    printf '\n  gateway   http://127.0.0.1:%s/  (front door: site when clean, drip when quarantined)\n' "${GATEWAY_PORT}"
    printf '  responder http://127.0.0.1:%s/health  (Stage 1 tarpit, measured directly)\n' "${RESPONDER_PORT}"
    printf '  console   http://127.0.0.1:%s/\n\n' "${CONSOLE_PORT}"
}

cmd_down() {
    local name pidfile pid
    for name in console gateway responder app; do
        pidfile="${RUN_DIR}/${name}.pid"
        [ -f "${pidfile}" ] || { say "stopped" "${name} (not running)"; continue; }
        pid="$(cat "${pidfile}")"
        if kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null || true
            local waited=0
            while kill -0 "${pid}" 2>/dev/null && [ ${waited} -lt 50 ]; do sleep 0.1; waited=$((waited + 1)); done
            kill -0 "${pid}" 2>/dev/null && kill -9 "${pid}" 2>/dev/null || true
            say "stopped" "${name} pid=${pid}"
        else
            say "stopped" "${name} (stale pidfile)"
        fi
        rm -f "${pidfile}"
    done
}

cmd_status() {
    local name pidfile pid state
    for name in app responder gateway console; do
        pidfile="${RUN_DIR}/${name}.pid"
        pid=""; state="stopped"
        if [ -f "${pidfile}" ]; then
            pid="$(cat "${pidfile}")"
            kill -0 "${pid}" 2>/dev/null && state="running"
        fi
        printf '%-10s %-8s pid=%-7s\n' "${name}" "${state}" "${pid:--}"
    done
    # The gateway has no health endpoint of its own - it is a front door, so the honest liveness
    # question is "does the front door answer, and how fast". A 404 here would be the stand-in site
    # answering, not a gateway fault, which is why this is labelled `probe` and carries a time.
    say "probe" "gateway  $(curl -s -o /dev/null -w '%{http_code} %{time_total}s' "http://127.0.0.1:${GATEWAY_PORT}/" || echo down)"
    say "health" "responder $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${RESPONDER_PORT}/health" || echo down)"
    say "health" "console  $(curl -s "http://127.0.0.1:${CONSOLE_PORT}/health" || echo down)"
    say "map" "$(grep -cv '^#' "${MAP}" 2>/dev/null || echo 0) address(es) in ${MAP}"
}

# The harness is proven or it is not: one unmapped request, one mapped request, both measured.
# Times are printed rather than asserted against a tight bound, because the drip is deliberately
# slow and a loaded box is not a regression - the assertion is "at least a second slower", which no
# amount of scheduling noise can produce from a 4 ms path.
cmd_verify() {
    local ip="${1:-127.0.0.1}"
    local fast slow body deception responder
    [ -x "${VENV}/bin/python" ] || die "no .venv"
    fast="$(curl -s -o /dev/null -w '%{http_code} %{time_total}' "http://127.0.0.1:${GATEWAY_PORT}/")" \
        || die "gateway not answering on ${GATEWAY_PORT}; run: bin/local-stack.sh up"
    say "unmapped" "gateway ${fast}"
    "${VENV}/bin/python" "${CONTROLLER}" --db "${STATE_DB}" --map "${MAP}" \
        --audit-log "${AUDIT_LOG}" --bypass-file "${BYPASS_FILE}" \
        claim "${ip}" --verdict confirmed --source local-stack-verify --ttl 300 --render >/dev/null \
        || die "controller claim failed"
    say "claimed" "${ip} -> $(grep -v '^#' "${MAP}" | awk -v ip="${ip}" '$1==ip{print $2}')"
    local wait=0
    while [ ${wait} -lt 20 ]; do
        deception="$(curl -sD- -o /dev/null -w '%{http_code} %{time_total}' "http://127.0.0.1:${GATEWAY_PORT}/" | tr -d '\r')"
        slow="${deception##* }"
        awk -v t="${slow}" 'BEGIN{exit !(t > 1.0)}' && break
        wait=$((wait + 1))
        sleep 0.5
    done
    say "observed" "map change picked up after $(awk -v w="${wait}" 'BEGIN{printf "%.1f", w*0.5}')s (gateway --map-ttl 2)"
    body="$(curl -s "http://127.0.0.1:${GATEWAY_PORT}/" | wc -c)"
    say "mapped" "gateway ${slow} (${body} byte body, $(printf '%s' "${deception}" | grep -i '^x-fleet-filter-deception' | cut -d' ' -f2-))"
    responder="$(curl -s -o /dev/null -w '%{http_code} %{time_total}' "http://127.0.0.1:${RESPONDER_PORT}/ai.html")"
    say "responder" "stage 1 drip ${responder}"
    "${VENV}/bin/python" "${CONTROLLER}" --db "${STATE_DB}" --map "${MAP}" \
        --audit-log "${AUDIT_LOG}" --bypass-file "${BYPASS_FILE}" \
        revoke "${ip}" --render >/dev/null || die "controller revoke failed"
    say "revoked" "${ip} removed from the map"
    "${VENV}/bin/python" - "${fast##* }" "${slow##* }" "${responder##* }" <<'PY'
import sys
fast, slow, responder = (float(v) for v in sys.argv[1:4])
failures = []
if fast > 1.0:
    failures.append("unmapped source was not fast: %.3fs" % fast)
if slow - fast < 1.0:
    failures.append("mapped source was not slowed: %.3fs vs %.3fs unmapped" % (slow, fast))
if responder < 1.0:
    failures.append("stage 1 responder did not drip: %.3fs" % responder)
if failures:
    sys.exit("FAIL  " + "; ".join(failures))
print("PASS  unmapped %.3fs, mapped %.3fs (+%.3fs), stage 1 drip %.3fs"
      % (fast, slow, slow - fast, responder))
PY
}

cmd_sync() {
    [ -x "${VENV}/bin/python" ] || die "no .venv"
    "${VENV}/bin/python" "${REPO_ROOT}/web/sync.py" --cache "${CACHE}"
}

cmd_logs() {
    local lines="${1:-20}"
    local name
    for name in app responder gateway console; do
        printf '=== %s (%s) ===\n' "${name}" "${LOG_DIR}/${name}.log"
        tail -n "${lines}" "${LOG_DIR}/${name}.log" 2>/dev/null || echo "(no log yet)"
    done
}

case "${1:-}" in
    up) shift || true; cmd_up ;;
    down) shift || true; cmd_down ;;
    status) shift || true; cmd_status ;;
    verify) shift || true; cmd_verify "$@" ;;
    sync) shift || true; cmd_sync ;;
    logs) shift || true; cmd_logs "$@" ;;
    *) sed -n '/^# Usage$/,/^#   bin\/local-stack.sh logs/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
