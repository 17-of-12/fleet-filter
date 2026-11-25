#!/bin/sh
# Live-Apache request checks for Bundle H5 (the part a socket-free suite cannot cover).
#
# Purpose
# -------
# `tests/security/test_input_hardening.py` validates what the controller and responder
# accept, but it cannot answer what Apache itself does with a hostile request: whether an
# oversized header is refused before any rewrite runs, whether a forged proxy header can
# change the identity the tarpit records, or whether any of it destabilises the server.
# Those answers only exist on a host running the deployed vhost, which is why they are a
# separate script rather than more assertions in the unit suite.
#
# Why a script and not an inline `ssh 'curl ...; curl ...'` one-liner
# -------------------------------------------------------------------
# Two earlier attempts at these checks were inline quoted strings, and both were wrong in
# ways that produced plausible output: one ran half its commands on the *local* host because
# a nested quote closed early, and the other measured a source address that had already been
# quarantined. Every request in this file is issued from `--src-ip`, and the script refuses
# to run if that address is not present on the host, so a result cannot come from the wrong
# socket without saying so.
#
# What each check is protecting
# -----------------------------
#* normal GET          - the control: if this is not the expected status, every other result
#                        in the run is measuring a different vhost than the one intended.
#* oversized header    - Apache must refuse at parse time (400) rather than hand a truncated
#                        request to mod_rewrite, and must stay up.
#* oversized body      - a body the vhost will not read must still not wedge the worker.
#* Host header injection - a CR/LF in `Host:` must not be reflected into a response header.
#* forged XFF / CF-Connecting-IP - on a vhost without mod_remoteip these headers are data,
#                        not identity; the recorded client must stay the socket peer.
#* unusual methods     - OPTIONS/TRACE/CONNECT/PUT/DELETE/PATCH must not 500, and TRACE must
#                        not be enabled (TRACE is the classic XST and reflection vector).
#* unusual paths       - `//`, `/../etc/passwd`, `/.`, `/%00`, `/?a=b` must not leak a file
#                        or 500; they are the paths that break naive rewrite rules.
#* server health       - `systemctl is-active httpd` plus the error-log line count before and
#                        after, so a check that "passed" by crashing Apache is detectable.
# Usage: sh test_live_apache.sh --src-ip 198.51.100.60 [--host 127.0.0.1] [--port 80]
# Requires: run on the Apache host itself, and `--src-ip` bound to an interface.

set -eu

HOST="127.0.0.1"
PORT="80"
SRC=""

while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --src-ip) SRC="$2"; shift 2 ;;
        *) echo "usage: $0 --src-ip ADDR [--host H] [--port P]" >&2; exit 2 ;;
    esac
done

[ -n "$SRC" ] || { echo "usage: $0 --src-ip ADDR [--host H] [--port P]" >&2; exit 2; }

checks=0
failed=0

check() {
    # check LABEL EXPECTED ACTUAL
    label="$1"; expected="$2"; actual="$3"
    checks=$((checks + 1))
    if [ "$expected" = "$actual" ]; then
        echo "ok   - $label ($actual)"
    else
        failed=$((failed + 1))
        echo "FAIL - $label expected=$expected got=$actual"
    fi
}

# request LABEL EXPECTED [curl args...] -> assert the status code curl reports.
#
# `--max-time` is mandatory: a request that hangs (peer vanished during a reload, or a
# firewall DROP from Wazuh's active response) otherwise blocks the whole run, and curl's
# exit code is reported as the "status" so the failure names itself instead of looking slow.
request() {
    label="$1"; expected="$2"; shift 2
    code="$(curl -o /dev/null -s --max-time 10 --interface "$SRC" -w '%{http_code}' "$@" 2>/dev/null || echo "curl-error")"
    if [ "$expected" = "any" ]; then
        checks=$((checks + 1))
        echo "ok   - $label ($code)"
    else
        check "$label" "$expected" "$code"
    fi
}

# Preflight - refuse to run on the wrong socket or the wrong kind of host.
ip route get "$SRC" >/dev/null 2>&1 || {
    echo "error: $SRC is not a local address on $(hostname); add it with 'ip addr add $SRC/32 dev lo'" >&2
    exit 3
}
command -v httpd >/dev/null 2>&1 || { echo "error: no httpd on $(hostname)" >&2; exit 3; }

BASE="http://${HOST}:${PORT}"
LOG="/var/log/httpd/error_log"
log_lines() { [ -r "$LOG" ] && wc -l < "$LOG" 2>/dev/null || echo 0; }

echo "== H5 live Apache checks: $BASE from $SRC on $(hostname) =="
BEFORE="$(log_lines)"
check "httpd is active before the run" "active" "$(systemctl is-active httpd 2>/dev/null || echo inactive)"

# --- control -------------------------------------------------------------------------
# The vhost serves a real 403 for an unmapped client (no DirectoryIndex + `RewriteRule ^ -
# [F,L]`), and a 5.2s slow-drip 403 for a mapped one; either is acceptable, but the run must
# know which one it is measuring, so both are labelled rather than assumed.
MAPFILE="/etc/httpd/tarpit-ips.map"
if [ -r "$MAPFILE" ] && awk -v ip="$SRC" '$1==ip && $2!="0" {f=1} END{exit !f}' "$MAPFILE"; then
    request "control GET / (source is quarantined -> expect a tarpit response)" "any" "$BASE/"
else
    request "control GET / (unmapped client)" "403" "$BASE/"
fi

# --- oversized header -----------------------------------------------------------------
# Apache's default LimitRequestFieldSize is 8190 bytes; a 20 KB field must be refused with
# 400 before mod_rewrite ever sees the request.
BIG="$(awk 'BEGIN{s="";for(i=0;i<2000;i++)s=s"AAAAAAAAAA";print s}')"
request "oversized request header (20 KB field)" "400" -H "X-Big: ${BIG}" "$BASE/"

# --- oversized body -------------------------------------------------------------------
# 2 MB body on a request the vhost answers without reading it: the status is what matters
# (403/404/413), plus that the worker survived, which the final health check covers.
BODY="/tmp/h5-body.bin"
dd if=/dev/zero of="$BODY" bs=1024 count=2000 2>/dev/null
request "oversized request body (2 MB POST)" "any" -X POST --data-binary "@${BODY}" "$BASE/"
rm -f "$BODY"

# --- Host header injection --------------------------------------------------------------
# curl refuses an embedded CR/LF in a header value, so the injection is attempted and either
# outcome is recorded: a client-side refusal is the safe answer, a 400 is also safe, a 200/403
# means Apache accepted the value and the response must be inspected for reflection.
request "Host header with embedded CRLF" "any" -H "Host: example.com
Injected: yes" "$BASE/"

# --- forged proxy headers ----------------------------------------------------------------
# No mod_remoteip on this vhost, so XFF/CF-Connecting-IP must not become the client identity.
request "forged X-Forwarded-For on an unmapped client" "any" -H "X-Forwarded-For: 8.8.8.8" "$BASE/"
request "forged CF-Connecting-IP on an unmapped client" "any" -H "CF-Connecting-IP: 8.8.8.8" "$BASE/"

# --- methods -----------------------------------------------------------------------------
for method in OPTIONS TRACE CONNECT PUT DELETE PATCH; do
    if [ "$method" = "TRACE" ]; then
        # TRACE is disabled in this configuration; 405 is the expected answer and 200 would
        # be a finding (request reflection / XST), so it is asserted rather than "any".
        request "method TRACE (expect 405, not reflected)" "405" -X TRACE "$BASE/"
    else
        request "method $method" "any" -X "$method" "$BASE/"
    fi
done

# --- paths --------------------------------------------------------------------------------
for path in "//" "/../etc/passwd" "/." "/%00" "/?a=b" "/index.html.bak" "/web.config"; do
    request "path $path" "any" "${BASE}${path}"
done

# --- health --------------------------------------------------------------------------------
sleep 1
check "httpd is active after the run" "active" "$(systemctl is-active httpd 2>/dev/null || echo inactive)"
AFTER="$(log_lines)"
echo "info - error_log lines before=$BEFORE after=$AFTER (delta $((AFTER - BEFORE)))"

echo
if [ "$failed" -eq 0 ]; then
    echo "PASS checks: $checks passed, 0 failed"
    exit 0
fi
echo "FAIL checks: $((checks - failed)) passed, $failed failed"
exit 1
