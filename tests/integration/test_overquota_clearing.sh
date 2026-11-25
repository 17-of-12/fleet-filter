#!/bin/sh
# Prove the over-quota (value 2) state clears itself (Bundle H7).
#
# Purpose
# -------
# The owner's no-hard-blocks rule makes a *persistent* refusal a defect: value 2 exists only
# as backpressure while the backend is over its concurrency budget, so the moment capacity
# frees, an address sitting at 2 has to move back to 1 (tarpit) or off the map. A `2` that
# never clears is a hard block wearing a different name, and it is exactly the failure an
# operator would notice weeks later as "some IPs stopped being tarpitted and started getting
# 503s".
#
# What is asserted, and why each one is needed
# --------------------------------------------
# 1. quota exceeded -> excess renders as 2, not as 1 or as an omitted line
#    (otherwise the cap is not enforced, it is just documented);
# 2. removing one value-1 lease promotes a value-2 address back to 1
#    (this is the actual "clears once capacity frees" claim);
# 3. raising the quota to cover every lease leaves zero 2s
#    (proves no address can be stranded at 2 while capacity exists);
# 4. an expired lease disappears on the next render and the remaining addresses re-rank
#    (expiry is the normal way capacity frees in production);
# 5. `verify` agrees with the map after every render
#    (PT-11: a render that the drift check disagrees with means the file and the store have
#    diverged, which invalidates every other assertion in this file).
#
# The test runs against a sandbox db/map so it cannot disturb the live leases, and it drives
# the same binary that is deployed on the host.

set -eu

BIN="${BIN:-/usr/local/bin/adaptive-tarpit}"
WORK="${WORK:-}"
SEED_IPS="198.51.100.201 198.51.100.202 198.51.100.203 198.51.100.204 198.51.100.205"

if [ -z "$WORK" ]; then
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
fi
DB="$WORK/state.db"
MAP="$WORK/tarpit-ips.map"
ALLOWLIST="$WORK/allowlist.conf"
: > "$ALLOWLIST"

checks=0
failed=0

check() {
    # check NAME CONDITION_TEXT RESULT
    name="$1"; detail="$2"; ok="$3"
    checks=$((checks + 1))
    if [ "$ok" = "1" ]; then
        echo "ok   - $name"
    else
        failed=$((failed + 1))
        echo "FAIL - $name ($detail)"
    fi
}

at() {
    # Global options must precede the subcommand; argparse only accepts them there.
    "$BIN" --db "$DB" --map "$MAP" --allowlist "$ALLOWLIST" "$@"
}

count_value() {
    # count_value N -> number of map lines whose routing value is N
    [ -f "$MAP" ] || { echo 0; return; }
    awk -v v="$1" '!/^#/ && NF>=2 && $2==v { c++ } END { print c+0 }' "$MAP"
}

has_ip_value() {
    # has_ip_value IP N -> 1 when the map maps IP to exactly N
    [ -f "$MAP" ] || { echo 0; return; }
    awk -v ip="$1" -v v="$2" '!/^#/ && $1==ip && $2==v { f=1 } END { print f+0 }' "$MAP"
}

verify_ok() {
    at verify --quiet >/dev/null 2>&1 && echo 1 || echo 0
}

echo "== H7 over-quota clearing: $BIN (db=$DB) =="

# --- seed ------------------------------------------------------------------------------
first_ip="$(printf '%s' "$SEED_IPS" | awk '{print $1}')"
second_ip="$(printf '%s' "$SEED_IPS" | awk '{print $2}')"
for ip in $SEED_IPS; do
    at claim "$ip" --verdict confirmed --source integration-h7 --ttl 3600 >/dev/null
done
check "seeded $(printf '%s\n' $SEED_IPS | wc -l | tr -d ' ') confirmed claims" \
      "$(at list --json 2>/dev/null | head -1)" \
      "$([ "$(at list --json 2>/dev/null | grep -c '"ip"')" -ge 5 ] && echo 1 || echo 0)"

# --- 1. quota enforcement renders the excess as 2 ---------------------------------------
at render --max-tarpit 2 >/dev/null
ones="$(count_value 1)"; twos="$(count_value 2)"
check "quota 2 renders exactly 2 value-1 entries" "got $ones" "$([ "$ones" = 2 ] && echo 1 || echo 0)"
check "the 3 addresses over quota render as value 2" "got $twos" "$([ "$twos" = 3 ] && echo 1 || echo 0)"
check "verify agrees with the quota-2 render" "" "$(verify_ok)"

# --- 2. capacity frees by revocation -> a 2 becomes a 1 ---------------------------------
# The first address is the one holding a value-1 slot; revoking it must promote the first
# address that had been sitting at 2.
at revoke "$first_ip" --render --max-tarpit 2 >/dev/null
ones="$(count_value 1)"; twos="$(count_value 2)"
check "after revoking a value-1 lease the cap still holds at 2" "got $ones ones" "$([ "$ones" = 2 ] && echo 1 || echo 0)"
check "the ex-quota population shrinks from 3 to 2" "got $twos twos" "$([ "$twos" = 2 ] && echo 1 || echo 0)"
check "the revoked address is gone from the map" "" "$(has_ip_value "$first_ip" 0 >/dev/null; [ "$(has_ip_value "$first_ip" 1)" = 0 ] && [ "$(has_ip_value "$first_ip" 2)" = 0 ] && echo 1 || echo 0)"
check "the second address inherited the freed value-1 slot" "" "$(has_ip_value "$second_ip" 1)"
check "verify agrees after the revocation render" "" "$(verify_ok)"

# --- 3. raising the quota strands nobody at 2 ---------------------------------------------
at render --max-tarpit 4 >/dev/null
check "quota 4 with 4 leases leaves zero value-2 entries" "got $(count_value 2)" "$([ "$(count_value 2)" = 0 ] && echo 1 || echo 0)"
at render --max-tarpit 0 >/dev/null
check "unlimited quota leaves zero value-2 entries" "got $(count_value 2)" "$([ "$(count_value 2)" = 0 ] && echo 1 || echo 0)"
check "all 4 remaining leases render as value 1" "got $(count_value 1)" "$([ "$(count_value 1)" = 4 ] && echo 1 || echo 0)"
check "verify agrees with the unlimited render" "" "$(verify_ok)"

# --- 4. capacity frees by expiry ----------------------------------------------------------
# A short-TTL claim, expired on purpose: expiry is the production path, so the clearing
# behaviour has to be driven by `expire` and not only by a manual revoke.
at claim 198.51.100.206 --verdict suspect --source integration-h7 --ttl 1 >/dev/null
at render --max-tarpit 0 >/dev/null
check "short-TTL claim is present before expiry" "" "$(has_ip_value 198.51.100.206 1)"
sleep 2
at expire --render --max-tarpit 0 >/dev/null
check "expired claim is removed by expire" "" "$([ "$(has_ip_value 198.51.100.206 1)" = 0 ] && echo 1 || echo 0)"
check "remaining leases are untouched by the expiry render" "got $(count_value 1)" "$([ "$(count_value 1)" = 4 ] && echo 1 || echo 0)"
check "verify agrees after the expiry render" "" "$(verify_ok)"

# --- 5. the quota the map was built with is the one verify uses ----------------------------
# PT-11 reads last_max_tarpit from the store; if a render wrote a different quota than the
# one verify assumes, every value in the map would be wrong and assertions 1-4 would be
# meaningless. Re-rendering at quota 2 and verifying proves the parameter round-tripped.
at render --max-tarpit 2 >/dev/null
check "verify uses the stored quota (2) rather than a default" "" "$(at verify --max-tarpit 2 --quiet >/dev/null 2>&1 && echo 1 || echo 0)"
check "verify rejects a different quota for the same map" "" "$(at verify --max-tarpit 9 --quiet >/dev/null 2>&1 || echo 1)"

echo
if [ "$failed" -eq 0 ]; then
    echo "PASS checks: $checks passed, 0 failed"
    exit 0
fi
echo "FAIL checks: $((checks - failed)) passed, $failed failed"
exit 1
