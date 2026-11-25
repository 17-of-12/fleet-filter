#!/usr/bin/env bash
# C6 - routing matrix: every listener x every client class x every protocol.
#
# The question this answers is narrower than "does Apache work": for each way a request can arrive,
# and for each way the controller can classify its source, does the enforcement action match the map?
# Cell expectations are *derived* from the live map rather than hardcoded, so the test cannot drift
# from the state it claims to check.
#
# IPv6 is out of scope by owner decision 2026-11-14 (see docs/container/canary-build-2026-11-14.md, V6);
# the matrix is IPv4-only and says so in its output rather than leaving a silent gap.
#
# Usage: bash test_routing_matrix.sh [host]   (default: run locally, i.e. execute on the target)
set -uo pipefail

MAP=/etc/httpd/tarpit-ips.map
ALLOWLIST=/etc/adaptive-tarpit/allowlist
PATH_UNDER_TEST=/ai.html          # a path that exists on every vhost, so 404s never mask routing
TIMEOUT=25
FAST_LIMIT=1.0                    # seconds; anything above is treated as a tarpitted (slow-drip) answer

# Listeners: label|url|extra curl args|whether client-IP fidelity is preserved (see note below)
LISTENERS=(
    "native-:80|http://10.30.72.19:80|""|yes"
    "backend-:8088|http://198.51.100.110:8088|""|yes"
    "gateway-:8443|https://198.51.100.111:8443|--http2|yes"
    "gateway-:8443-h1|https://198.51.100.111:8443|--http1.1|yes"
    "container-:18080|http://127.0.0.1:18080|""|no"
)

# Client sources are resolved from the map per class (see `awk` in main), never hardcoded.
probe() { # probe <url> <extra args> <source ip> -> "status time"
    local url="$1" extra="$2" src="$3"
    if [[ -n "$src" ]]; then
        curl -sk -o /dev/null -w '%{http_code} %{time_total}' --interface "$src" --max-time "$TIMEOUT" "$url" 2>/dev/null || echo "000 0"
    else
        echo "n/a 0"
    fi
}

main() {
    echo "# Routing matrix - $(hostname -f) - $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "Path requested: \`$PATH_UNDER_TEST\` on every listener. Address classes resolved from \`$MAP\`."
    echo "IPv6: out of scope (owner decision 2026-11-14). HTTP/2 is exercised on the gateway (ALPN);"
    echo "the native and backend vhosts are pinned to \`Protocols http/1.1\`, and the container's h2 is"
    echo "not reachable without prior-knowledge on a port whose client IP is the podman bridge."
    echo
    printf '| listener | protocol | client class | source | status | time (s) | verdict |\n'
    printf '|---|---|---|---|---|---|---|\n'
    local failures=0
    for entry in "${LISTENERS[@]}"; do
        IFS='|' read -r label url extra fidelity <<< "$entry"
        local protocol="HTTP/1.1"
        [[ "$extra" == "--http2" ]] && protocol="HTTP/2"
        [[ "$extra" == "--http1.1" ]] && protocol="HTTP/1.1 (explicit)"
        for value in 0 1 2; do
            case "$value" in
                0) klass="allowlisted/normal" ;;
                1) klass="tarpitted" ;;
                2) klass="over-quota" ;;
            esac
            src=$(awk -v v="$value" 'NR>2 && $2==v {print $1; exit}' "$MAP" 2>/dev/null)
            if [[ -z "$src" ]]; then
                printf '| %s | %s | %s | - | - | - | no address in this class |\n' "$label" "$protocol" "$klass"
                continue
            fi
            if [[ "$fidelity" == "no" && "$src" != "127.0.0.1" ]]; then
                # Documented container limitation: podman bridge NAT rewrites the source to 10.89.0.1,
                # so a per-client class cannot be exercised through the container without proxy protocol.
                printf '| %s | %s | %s | %s | - | - | not testable (client IP is the podman bridge) |\n' \
                    "$label" "$protocol" "$klass" "$src"
                continue
            fi
            read -r code t <<< "$(probe "$url$PATH_UNDER_TEST" "$extra" "$src")"
            verdict="fast"
            awk -v t="$t" -v l="$FAST_LIMIT" 'BEGIN{exit !(t>l)}' && verdict="slow"
            expected="fast"; [[ "$value" == "1" || "$value" == "2" ]] && [[ "$label" != container* ]] && expected="slow"
            [[ "$value" == "0" ]] && expected="fast"
            if [[ "$verdict" == "$expected" ]]; then mark="ok"; else mark="MISMATCH"; failures=$((failures + 1)); fi
            printf '| %s | %s | %s | %s | %s | %s | %s (expected %s) |\n' \
                "$label" "$protocol" "$klass" "$src" "$code" "$t" "$mark" "$expected"
        done
    done
    echo
    echo "result: $failures mismatch(es)"
    [[ $failures -eq 0 ]]
}

main "$@"
