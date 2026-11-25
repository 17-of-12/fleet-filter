#!/usr/bin/env bash
# Report the certificate the gateway is configured to serve, and whether it is close to expiring.
#
# This exists because renewal has two failure modes and only one of them is loud. A renewal that
# fails to run leaves a certificate that expires on a known date - silent until the day it breaks.
# A renewal that runs and does not take effect is the one the deploy hook catches by reading the
# served certificate back. This check covers the first: it is meant to be run on a timer and to
# exit non-zero while there is still time to act.
#
# Usage:
#   gateway-cert-status.sh [--policy FILE] [--warn-days N] [--json]
#
# Exit: 0 healthy, 1 within the warning window or already expired, 2 cannot read the material.

set -euo pipefail

POLICY="/etc/fleet-filter-gateway/policy.toml"
WARN_DAYS=21
JSON=0

die() { echo "cert-status: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --policy) POLICY=${2:?--policy needs a value}; shift 2 ;;
        --warn-days) WARN_DAYS=${2:?--warn-days needs a value}; shift 2 ;;
        --json) JSON=1; shift ;;
        --help|-h) sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -r "$POLICY" ] || die "cannot read policy: $POLICY"
policy_value() {
    grep -E "^[[:space:]]*$1[[:space:]]*=" "$POLICY" | head -1 |
        sed -E 's/^[^=]*=[[:space:]]*"([^"]*)".*$/\1/'
}

cert=$(policy_value tls_cert)
[ -n "$cert" ] || { echo "no TLS listener in $POLICY"; exit 0; }
[ -r "$cert" ] || die "cannot read certificate: $cert"

subject=$(openssl x509 -in "$cert" -noout -subject | sed 's/^subject=//')
issuer=$(openssl x509 -in "$cert" -noout -issuer | sed 's/^issuer=//')
not_after=$(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)
end_epoch=$(date -d "$not_after" +%s 2>/dev/null || echo 0)
now=$(date +%s)
days=$(( (end_epoch - now) / 86400 ))

if [ "$JSON" = "1" ]; then
    printf '{"certificate":"%s","subject":"%s","issuer":"%s","not_after":"%s","days_remaining":%d,"warn_days":%d}\n' \
        "$cert" "$subject" "$issuer" "$not_after" "$days" "$WARN_DAYS"
else
    echo "certificate: $cert"
    echo "subject:     $subject"
    echo "issuer:      $issuer"
    echo "not after:   $not_after (${days}d)"
fi

if [ "$days" -lt "$WARN_DAYS" ]; then
    echo "cert-status: ${days}d remaining is inside the ${WARN_DAYS}d window" >&2
    exit 1
fi
