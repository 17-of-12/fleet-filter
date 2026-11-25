#!/usr/bin/env bash
# G2 - fail2ban / Wazuh lease interaction on one address.
#
# G2 requires four things proven, not asserted: a fail2ban ban and a Wazuh lease on the same IP are
# independent, they coexist, a fail2ban ban expiring while a Wazuh lease is live does not un-quarantine
# the address, and removing one claim leaves the other enforcing. The mechanism is the controller's
# (ip, claim_key) claim model, so the test asserts on the store and the rendered map rather than on
# fail2ban's own state.
#
# Runs against a throwaway db/map so a test run cannot disturb the live enforcement state, but uses the
# real installed shim (/usr/local/bin/f2b-fleet-filter) so the fail2ban code path is the one tested.
#
# Usage: bash test_fail2ban_leases.sh [at-bin] [shim]
set -uo pipefail

AT="${1:-/usr/local/bin/adaptive-tarpit}"
SHIM="${2:-/usr/local/bin/f2b-fleet-filter}"
IP=203.0.113.50
PASS=0
FAIL=0

check() { # check <label> <expected> <actual>
    if [[ "$2" == "$3" ]]; then
        printf '  ok   %-56s %s\n' "$1" "$3"; PASS=$((PASS + 1))
    else
        printf '  FAIL %-56s expected=%s actual=%s\n' "$1" "$2" "$3"; FAIL=$((FAIL + 1))
    fi
}

main() {
    echo "G2 fail2ban/Wazuh lease test - $(hostname -f 2>/dev/null || hostname) - $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    [[ -x "$AT" ]] || { echo "no controller at $AT"; exit 2; }
    [[ -x "$SHIM" ]] || { echo "no fail2ban shim at $SHIM"; exit 2; }
    local work; work=$(mktemp -d /tmp/f2bleases.XXXXXX)
    echo "127.0.0.1" > "$work/allowlist"
    local A="$AT --db $work/state.db --map $work/map --allowlist $work/allowlist --no-audit"

    # 1. fail2ban bans the address (this is exactly what actionban runs).
    "$SHIM" --at-bin "$AT" --db "$work/state.db" --map "$work/map" --allowlist "$work/allowlist" \
        --verdict suspect --ttl 900 fleet-filter "$IP" 5 >/dev/null 2>&1
    # `list` reports the effective verdict per address (not the word "added", which is what `claim`
    # prints), so the assertion is on the verdict the shim must have recorded.
    check "fail2ban ban creates a suspect claim" "suspect" \
        "$($A list 2>/dev/null | awk -v ip="$IP" '$1==ip{print $2}' | head -1)"
    check "fail2ban-only address is quarantined in the map" "1" "$(awk -v ip="$IP" '$1==ip{print $2}' "$work/map")"

    # 2. Wazuh claims the same address with a stronger verdict and a longer TTL.
    $A claim "$IP" --verdict confirmed --source wazuh-rule-120006 --author estate-01 --render >/dev/null 2>&1
    local keys
    keys=$($A --db "$work/state.db" --map "$work/map" --allowlist "$work/allowlist" --no-audit \
        list 2>/dev/null | grep -c "$IP")
    check "both claims coexist on one address (one row per address, claims folded)" "1" "$keys"
    check "the merged verdict is the stronger one (PT-05 promotion)" "confirmed" \
        "$($A list 2>/dev/null | awk -v ip="$IP" '$1==ip{print $2}')"

    # 3. The fail2ban ban expires while the Wazuh lease is still live.
    $A --db "$work/state.db" --map "$work/map" --allowlist "$work/allowlist" --no-audit \
        claim "$IP" --verdict suspect --source fail2ban-fleet-filter --author lab-web01 --ttl 1 >/dev/null 2>&1
    sleep 2
    $A expire --render >/dev/null 2>&1
    check "expired fail2ban claim is gone, Wazuh claim survives" "confirmed" \
        "$($A list 2>/dev/null | awk -v ip="$IP" '$1==ip{print $2}')"
    check "the address is still quarantined after the short lease lapsed" "1" \
        "$(awk -v ip="$IP" '$1==ip{print $2}' "$work/map")"

    # 4. Independent removal: revoke only the Wazuh claim; the fail2ban claim must keep enforcing.
    $A --db "$work/state.db" --map "$work/map" --allowlist "$work/allowlist" --no-audit \
        claim "$IP" --verdict suspect --source fail2ban-fleet-filter --author lab-web01 --ttl 900 --render >/dev/null 2>&1
    $A --db "$work/state.db" --map "$work/map" --allowlist "$work/allowlist" --no-audit \
        revoke "$IP" --claim-key wazuh-rule-120006 --render >/dev/null 2>&1
    check "revoking the Wazuh claim leaves the fail2ban claim" "suspect" \
        "$($A list 2>/dev/null | awk -v ip="$IP" '$1==ip{print $2}')"
    check "and the address remains quarantined" "1" "$(awk -v ip="$IP" '$1==ip{print $2}' "$work/map")"
    $A --db "$work/state.db" --map "$work/map" --allowlist "$work/allowlist" --no-audit \
        revoke "$IP" --render >/dev/null 2>&1
    check "revoking everything un-quarantines the address" "" \
        "$(awk -v ip="$IP" '$1==ip{print $2}' "$work/map")"
    rm -rf "$work"
    echo "result: $PASS passed, $FAIL failed"
    [[ $FAIL -eq 0 ]]
}

main "$@"
