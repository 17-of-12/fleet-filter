#!/usr/bin/env bash
# gateway-reload.sh - reload the gateway's policy and prove it happened.
#
# Why a script and not "systemctl reload": a reload that is sent is not a reload that took effect. The
# gateway logs what it did with the new policy - accepted, unchanged, or rejected with the old one kept
# - and that line is the only evidence. This sends the signal and waits for the line, so an agent or a
# deployment step can rely on the result rather than on a zero exit status.
#
# Usage:
#   gateway-reload.sh                      # systemd unit, journal evidence
#   gateway-reload.sh --pid FILE --log FILE  # a gateway started by hand
#   gateway-reload.sh --timeout 15
#
# Exit status: 0 when the reload was confirmed, 1 when it was rejected or the confirmation never
# appeared, 2 when the signal could not be sent.

set -euo pipefail

UNIT="fleet-filter-gateway"
PIDFILE=""
LOGFILE=""
TIMEOUT=15

die() { echo "gateway-reload: $*" >&2; exit 1; }
note() { echo "gateway-reload: $*" >&2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --unit) UNIT=${2:?--unit needs a value}; shift 2 ;;
        --pid) PIDFILE=${2:?--pid needs a file}; shift 2 ;;
        --log) LOGFILE=${2:?--log needs a file}; shift 2 ;;
        --timeout) TIMEOUT=${2:?--timeout needs seconds}; shift 2 ;;
        --help|-h) sed -n '3,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

since=$(date '+%Y-%m-%d %H:%M:%S')
if [ -n "$PIDFILE" ]; then
    kill -HUP "$(cat "$PIDFILE")" || die "could not signal the process in $PIDFILE"
else
    systemctl kill --signal=HUP "$UNIT" || die "could not signal $UNIT"
fi
note "sent SIGHUP"

# The three lines the gateway can print, taken from the binary rather than from this script's help
# text (`gateway/src/main.rs`: `println!("policy reload ok: ...")`, `println!("policy reload:
# unchanged (...)")`, `eprintln!("policy reload rejected: ...")`). The note-shaped one is the only one
# with the colon before the word, and the pattern this script used to carry - `policy reload
# (ok|: unchanged|rejected)` - needed a space that the binary does not print, so an unchanged reload
# was invisible and a healthy gateway timed the script out. Measured 2026-11-25 on a lab listener:
# the log had `policy reload: unchanged (policy version=deploy-115560-8806 ...)` and the script said
# "no reload confirmation within 15s".
RELOAD_LINE='policy reload (ok|rejected)|policy reload: (unchanged|accepted)'

evidence() {
    if [ -n "$LOGFILE" ]; then
        [ -f "$LOGFILE" ] && tail -50 "$LOGFILE" | grep -E "$RELOAD_LINE" | tail -1
    else
        journalctl -u "$UNIT" --since "$since" --no-pager -o cat 2>/dev/null |
            grep -E "$RELOAD_LINE" | tail -1
    fi
}

for _ in $(seq 1 "$TIMEOUT"); do
    line=$(evidence || true)
    case "$line" in
        *"rejected"*) die "the gateway refused the policy and kept the old one: ${line}" ;;
        *"reload ok"*|*"unchanged"*) note "confirmed: ${line}"; exit 0 ;;
    esac
    sleep 1
done

die "no reload confirmation within ${TIMEOUT}s; check the journal for this unit"
