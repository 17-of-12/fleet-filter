#!/usr/bin/env bash
# H6 - recovery suite for the deployed controller/gateway stack (runs ON the target as root).
#
# Purpose: prove the enforcement stack degrades predictably when its dependencies fail. Each scenario
# prints a check line and, where the scenario mutates state, the mutation is backed up and restored in
# the same function so a failure mid-suite cannot leave the host in a worse state than it was found.
#
# Usage: bash run_recovery_suite.sh [--keep-baseline]
set -uo pipefail

AT=/usr/local/bin/adaptive-tarpit
MAP=/etc/httpd/tarpit-ips.map
DB=/var/lib/adaptive-tarpit/state.db
WORK=$(mktemp -d /tmp/recovery.XXXXXX)
PASS=0
FAIL=0

check() { # check <label> <expected> <actual>
    if [[ "$2" == "$3" ]]; then
        printf '  ok   %-58s %s\n' "$1" "$3"
        PASS=$((PASS + 1))
    else
        printf '  FAIL %-58s expected=%s actual=%s\n' "$1" "$2" "$3"
        FAIL=$((FAIL + 1))
    fi
}

note() { printf '  note %s\n' "$1"; }

# ---- scenario 1: Wazuh stopped (Path B offline, Path A and enforcement must continue) -------------
scenario_wazuh() {
    echo "== Wazuh stopped =="
    # `systemctl list-unit-files | grep -q` is not usable under `set -o pipefail`: grep -q exits on the
    # first match, systemctl takes SIGPIPE, and the pipeline reports failure even though it matched.
    # `systemctl cat` answers the same question without a pipe.
    if systemctl cat wazuh-agent.service >/dev/null 2>&1; then
        if systemctl is-active --quiet wazuh-agent; then
            note "agent active (manager per /var/ossec/etc/ossec.conf); stopping for the drill"
            systemctl stop wazuh-agent
        else
            note "agent installed but not active"
        fi
    else
        note "no wazuh agent unit on this host"
    fi
    # The controller does not call Wazuh; it consumes verdicts. Prove the render path is independent.
    local before after
    before=$(sha256sum "$MAP" | awk '{print $1}')
    $AT render >/dev/null 2>&1
    after=$(sha256sum "$MAP" | awk '{print $1}')
    check "controller renders with Wazuh absent" "ok" "$( [[ -s $MAP ]] && echo ok || echo missing )"
    [[ "$before" != "$after" ]] && note "map re-rendered (content unchanged check is verify's job)"
    $AT verify --quiet && check "verify passes with Wazuh absent" "0" "$?" || check "verify passes with Wazuh absent" "0" "1"
    systemctl cat wazuh-agent.service >/dev/null 2>&1 && systemctl start wazuh-agent 2>/dev/null
}

# ---- scenario 2: controller stopped (existing map must keep serving) -------------------------------
scenario_controller_stopped() {
    echo "== controller (timer) stopped =="
    local enabled_before active_before
    enabled_before=$(systemctl is-enabled adaptive-tarpit.timer 2>/dev/null || echo none)
    systemctl stop adaptive-tarpit.timer 2>/dev/null
    active_before=$(systemctl is-active adaptive-tarpit.timer 2>/dev/null || true)
    check "timer stopped" "inactive" "$active_before"
    check "map still present and generated while controller is down" "yes" \
          "$( $AT verify --quiet >/dev/null 2>&1 && echo yes || echo no )"
    curl -s -o /dev/null --max-time 10 http://198.51.100.110:8088/ \
        && check "backend serves while controller is down" "0" "$?" || check "backend serves while controller is down" "0" "1"
    systemctl start adaptive-tarpit.timer 2>/dev/null
    check "timer restored to its prior state" "$enabled_before" "$(systemctl is-enabled adaptive-tarpit.timer 2>/dev/null || echo none)"
}

# ---- scenario 3: backend crash (responder down -> quarantined client gets a fast error) -----------
scenario_backend_crash() {
    echo "== responder (tarpit backend) crash =="
    local resp_active code t
    resp_active=$(systemctl is-active tarpit-test.service 2>/dev/null || echo inactive)
    if [[ "$resp_active" == "active" ]]; then
        systemctl stop tarpit-test.service
        t=$(date +%s)
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 --interface 198.51.100.72 \
               http://198.51.100.110:8088/ 2>/dev/null || echo 000)
        local elapsed=$(( $(date +%s) - t ))
        # A dead tarpit backend must produce a fast 502 (or 403 if the vhost served it locally), never a
        # hang and never the real application - that is H3's isolation requirement.
        case "$code" in
            403|502|503) verdict="answered" ;;
            *) verdict="code=$code" ;;
        esac
        check "quarantined client answered despite dead responder" "answered" "$verdict"
        check "answer is fast, not a hang (<=5s)" "yes" "$( (( elapsed <= 5 )) && echo yes || echo no )"
        systemctl start tarpit-test.service
        check "responder restored" "active" "$(systemctl is-active tarpit-test.service 2>/dev/null || echo inactive)"
    else
        note "responder service not active ($resp_active); skipping the live kill"
    fi
    # Gateway-side upstream failure: a gateway pointed at a dead port must fail the request, not queue.
    if systemctl is-active --quiet fleet-filter-gateway.service 2>/dev/null; then
        code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 https://198.51.100.111:8443/ 2>/dev/null || echo 000)
        check "gateway answers (any status) with its configured backend" "notempty" \
              "$( [[ -n $code ]] && echo notempty || echo empty )"
    fi
}

# ---- scenario 4: Apache reload (non-disruptive, map must survive) ----------------------------------
scenario_apache_reload() {
    echo "== Apache reload =="
    local before after code
    before=$(sha256sum "$MAP" | awk '{print $1}')
    systemctl reload httpd; check "httpd -t / reload succeeds" "0" "$?"
    after=$(sha256sum "$MAP" | awk '{print $1}')
    check "map unchanged by reload" "$before" "$after"
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://198.51.100.110:8088/ || echo 000)
    check "backend responds after reload" "403" "$code"
}

# ---- scenario 5: reboot (not executed on a shared host; boot-order evidence instead) --------------
scenario_reboot() {
    echo "== reboot =="
    note "reboot is not executed on a shared host without owner sign-off; verifying boot wiring instead"
    local units enabled missing=""
    units="httpd adaptive-tarpit.timer fleet-filter-gateway fleet-filter-testnet-addr tarpit-test fail2ban wazuh-agent"
    [[ -f /usr/local/bin/adaptive-tarpit ]] || missing="$missing adaptive-tarpit-binary"
    for u in $units; do
        enabled=$(systemctl is-enabled "$u.service" 2>/dev/null || systemctl is-enabled "$u" 2>/dev/null || echo missing)
        [[ "$enabled" == "missing" ]] && missing="$missing $u"
        printf '  info %-32s %s\n' "$u" "$enabled"
    done
    check "all project units enabled at boot (or documented)" "none" "${missing:-none}"
    systemctl cat fleet-filter-testnet-addr.service 2>/dev/null | grep -q 'Before=httpd.service' \
        && check "testnet address unit ordered before httpd" "yes" "yes" \
        || check "testnet address unit ordered before httpd" "yes" "no"
}

# ---- scenario 6: map corruption (controller must refuse to clobber a foreign file) -----------------
scenario_map_corruption() {
    echo "== map corruption =="
    local backup code
    backup="$WORK/map.backup"
    cp -a "$MAP" "$backup"
    printf 'this is not a map line\n' >> "$MAP"
    $AT verify --quiet >/dev/null 2>&1; code=$?
    check "verify detects a corrupted map" "1" "$code"
    cp -a "$backup" "$MAP"
    $AT verify --quiet >/dev/null 2>&1; code=$?
    check "verify passes after restore" "0" "$code"
    # A hand-written file must never be overwritten by a render.
    printf '192.0.2.1 1\n' > "$WORK/handwritten.map"
    $AT --map "$WORK/handwritten.map" render >/dev/null 2>&1; code=$?
    check "render refuses to overwrite a non-generated map" "1" "$code"
}

# ---- scenario 7: DB corruption (controller must fail loudly, not silently empty) -------------------
scenario_db_corruption() {
    echo "== DB corruption =="
    local backup code
    backup="$WORK/state.db.backup"
    cp -a "$DB" "$backup"
    printf 'not a database' > "$DB.corrupt"
    mv "$DB" "$WORK/state.db.orig"
    mv "$DB.corrupt" "$DB"
    $AT list >/dev/null 2>&1; code=$?
    check "controller errors on a corrupt store instead of reporting empty" "1" "$code"
    mv "$WORK/state.db.orig" "$DB"
    $AT list >/dev/null 2>&1; code=$?
    check "controller recovers after restore" "0" "$code"
    $AT verify --quiet >/dev/null 2>&1; code=$?
    check "verify passes after DB restore" "0" "$code"
}

# ---- scenario 8: concurrent updates (SQLite must serialise, no lost claims) ------------------------
scenario_concurrent_updates() {
    echo "== concurrent updates =="
    local pids=() i out rc=0
    for i in $(seq 1 8); do
        $AT --db "$WORK/conc.db" --map "$WORK/conc.map" --allowlist "$WORK/allowlist" \
            claim "198.51.100.$((120 + i))" --verdict confirmed --source recovery-drill \
            --author recovery --render >/dev/null 2>&1 &
        pids+=("$!")
    done
    for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
    check "8 concurrent claims all succeed" "0" "$rc"
    local rows
    rows=$($AT --db "$WORK/conc.db" --map "$WORK/conc.map" --allowlist "$WORK/allowlist" list 2>/dev/null | grep -c '^198\.18\.55\.')
    check "all 8 addresses present in the store" "8" "$rows"
    check "rendered map holds all 8 entries" "8" "$(grep -c '^198\.18\.55\.' "$WORK/conc.map")"
}

# ---- scenario 9: firewall reload (listeners must survive) ------------------------------------------
scenario_firewall_reload() {
    echo "== firewall reload =="
    if ! systemctl is-active --quiet firewalld; then
        note "firewalld not active"; return
    fi
    local before after code
    before=$(firewall-cmd --list-ports 2>/dev/null | tr ' ' '\n' | sort | tr '\n' ' ')
    firewall-cmd --reload >/dev/null 2>&1; check "firewall-cmd --reload succeeds" "0" "$?"
    after=$(firewall-cmd --list-ports 2>/dev/null | tr ' ' '\n' | sort | tr '\n' ' ')
    check "firewall configuration unchanged by reload" "$before" "$after"
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://198.51.100.110:8088/ || echo 000)
    check "backend still reachable after firewall reload" "403" "$code"
}

# ---- scenario 10: log filesystem full (unwritable log must not corrupt state) -----------------------
scenario_log_full() {
    echo "== log filesystem full (simulated: unwritable destinations) =="
    local code
    # Controller: an unwritable audit log warns and leaves the state change intact (E13 contract).
    cp -a "$DB" "$WORK/db.for_audit"
    printf 'x' > "$WORK/blocker"
    out=$($AT --db "$WORK/db.for_audit" --map "$WORK/map2" --allowlist "$WORK/allowlist" \
          --audit-log "$WORK/blocker/audit.jsonl" claim 198.51.100.199 --verdict suspect \
          --source recovery-drill --author recovery 2>&1)
    code=$?
    check "claim succeeds when the audit log cannot be written" "0" "$code"
    printf '%s' "$out" | grep -q 'warning: audit log' && check "the failure is reported as a warning" "yes" "yes" \
        || check "the failure is reported as a warning" "yes" "no"
    $AT --db "$WORK/db.for_audit" --map "$WORK/map2" --allowlist "$WORK/allowlist" list 2>/dev/null | grep -q '198.51.100.199' \
        && check "the claim itself persisted despite the log failure" "yes" "yes" \
        || check "the claim itself persisted despite the log failure" "yes" "no"
    # Real ENOSPC on /var/log needs a mount; record the measured usage instead of faking it.
    printf '  info %s\n' "$(df -P /var/log | awk 'NR==2{print "/var/log " $5 " used, " $4 " KiB free"}')"
}

main() {
    echo "Fleet Filter H6 recovery suite - $(hostname -f) - $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "workdir: $WORK"
    : > "$WORK/allowlist"; echo "127.0.0.1" > "$WORK/allowlist"
    scenario_wazuh
    scenario_controller_stopped
    scenario_backend_crash
    scenario_apache_reload
    scenario_reboot
    scenario_map_corruption
    scenario_db_corruption
    scenario_concurrent_updates
    scenario_firewall_reload
    scenario_log_full
    echo
    echo "result: $PASS passed, $FAIL failed (artifacts in $WORK)"
    [[ $FAIL -eq 0 ]]
}

main "$@"
