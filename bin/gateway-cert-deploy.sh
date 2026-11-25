#!/usr/bin/env bash
# Install a renewed certificate for the gateway, reload it, and prove the new one is being served.
#
# This is the hook any ACME client calls after a successful renewal. It is deliberately client-
# agnostic: certbot, acme.sh and lego all end at "here is a new certificate and key", and the part
# that can go wrong is not the issuance, it is the handover.
#
# Why each step exists:
#
#   * Key match, expiry and optional host check run BEFORE anything is installed. A renewal that
#     produced a mismatched pair is unusual, but installing one takes the listener from "old
#     certificate" to "no working listener", and the old certificate is the better failure.
#   * The install is a rename within the destination directory, so a reader (the gateway on SIGHUP)
#     sees either the old file or the new one, never a half-written one.
#   * Ownership is set to the service account. Measured on lab-web01: a 0600 key owned by root is
#     not readable by a service running as fleet-filter-gw, and the gateway now loads TLS before
#     binding, so that mistake surfaces as a failed start rather than a silent downgrade.
#   * The reload is a signal, and the signal is not the proof. The script connects to the listener,
#     reads the served certificate, and compares its fingerprint with the one just installed. A
#     reload that logs success while serving the old certificate is the failure this step exists to
#     catch - it happened on 2026-11-24 when the reload compared policy digests and not TLS
#     material, and the journal said "unchanged" while the old certificate stayed in service.
#   * If the served certificate is still the old one, the previous files are restored and reloaded,
#     so the failed attempt leaves the listener exactly as it was.
#
# Usage:
#   gateway-cert-deploy.sh --cert NEW.crt --key NEW.key --policy POLICY.toml \
#       [--unit fleet-filter-gateway] [--pid PID] [--user fleet-filter-gw] \
#       [--group fleet-filter-gw] [--min-days 7] [--expect-host NAME] [--no-verify]
#
# certbot:  --deploy-hook '/usr/local/sbin/fleet-filter-cert-deploy --policy /etc/.../policy.toml --unit fleet-filter-gateway'
# The renewal variables certbot exports (RENEWED_LINEAGE, RENEWED_DOMAINS) are ignored here on
# purpose: the destination comes from the policy, because the policy is what the process reads.

set -euo pipefail

CERT=""
KEY=""
POLICY="/etc/fleet-filter-gateway/policy.toml"
UNIT=""
PIDFILE=""
USER_NAME="fleet-filter-gw"
GROUP_NAME="fleet-filter-gw"
MIN_DAYS=7
EXPECT_HOST=""
VERIFY=1
DEST_CERT=""
DEST_KEY=""

die() { echo "cert-deploy: $*" >&2; exit 1; }
note() { echo "cert-deploy: $*" >&2; }

usage() {
    sed -n '3,40p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --cert) CERT=${2:?--cert needs a value}; shift 2 ;;
        --key) KEY=${2:?--key needs a value}; shift 2 ;;
        --policy) POLICY=${2:?--policy needs a value}; shift 2 ;;
        --unit) UNIT=${2:?--unit needs a value}; shift 2 ;;
        --pid) PIDFILE=${2:?--pid needs a value}; shift 2 ;;
        --user) USER_NAME=${2:?--user needs a value}; shift 2 ;;
        --group) GROUP_NAME=${2:?--group needs a value}; shift 2 ;;
        --min-days) MIN_DAYS=${2:?--min-days needs a value}; shift 2 ;;
        --expect-host) EXPECT_HOST=${2:?--expect-host needs a value}; shift 2 ;;
        --dest-cert) DEST_CERT=${2:?--dest-cert needs a value}; shift 2 ;;
        --dest-key) DEST_KEY=${2:?--dest-key needs a value}; shift 2 ;;
        --no-verify) VERIFY=0; shift ;;
        --help|-h) usage 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$CERT" ] || die "--cert is required"
[ -n "$KEY" ] || die "--key is required"
[ -r "$CERT" ] || die "cannot read certificate: $CERT"
[ -r "$KEY" ] || die "cannot read key: $KEY"

# --- destination ------------------------------------------------------------
# The policy names the files the process reads. Reading them from the policy rather than from a
# second configuration keeps one source of truth: a renewal can never install somewhere the
# gateway is not looking.
if [ -z "$DEST_CERT" ] || [ -z "$DEST_KEY" ]; then
    [ -r "$POLICY" ] || die "cannot read policy: $POLICY"
    policy_value() {
        # A top-level `key = "value"` line; values are quoted paths in this schema. The `|| true`
        # matters: under `set -e` with `pipefail`, an absent key returns grep's 1 through the
        # substitution and kills the script before the caller can say what is missing.
        grep -E "^[[:space:]]*$1[[:space:]]*=" "$POLICY" 2>/dev/null | head -1 |
            sed -E 's/^[^=]*=[[:space:]]*"([^"]*)".*$/\1/' || true
    }
    [ -n "$DEST_CERT" ] || DEST_CERT=$(policy_value tls_cert)
    [ -n "$DEST_KEY" ] || DEST_KEY=$(policy_value tls_key)
    if [ -z "$DEST_CERT" ] || [ -z "$DEST_KEY" ]; then
        note "policy $POLICY declares no tls_cert/tls_key; nothing to install"
        note "install-only mode requires --dest-cert and --dest-key"
        exit 0
    fi
fi

for path in "$DEST_CERT" "$DEST_KEY"; do
    dir=$(dirname "$path")
    [ -d "$dir" ] || die "destination directory does not exist: $dir"
done

# Only now is a reload target required: a policy with no TLS listener has nothing to reload, and
# demanding one before reading the policy turned "nothing to do" into an error.
if [ "$VERIFY" = "1" ] && [ -z "$UNIT" ] && [ -z "$PIDFILE" ]; then
    die "either --unit or --pid is required to reload (or --no-verify to install only)"
fi

# --- preflight --------------------------------------------------------------
openssl x509 -in "$CERT" -noout 2>/dev/null || die "not a PEM certificate: $CERT"
openssl pkey -in "$KEY" -noout 2>/dev/null || die "not a PEM private key: $KEY"

cert_pub=$(openssl x509 -in "$CERT" -noout -pubkey 2>/dev/null)
key_pub=$(openssl pkey -in "$KEY" -pubout 2>/dev/null)
if [ "$cert_pub" != "$key_pub" ]; then
    die "certificate and key do not match; refusing to install"
fi

if ! openssl x509 -in "$CERT" -noout -checkend $((MIN_DAYS * 86400)) >/dev/null 2>&1; then
    expiry=$(openssl x509 -in "$CERT" -noout -enddate 2>/dev/null | cut -d= -f2)
    die "certificate expires within ${MIN_DAYS}d ($expiry); refusing to install"
fi

if [ -n "$EXPECT_HOST" ]; then
    if ! openssl x509 -in "$CERT" -noout -checkhost "$EXPECT_HOST" 2>/dev/null | grep -q "does match"; then
        die "certificate does not cover $EXPECT_HOST"
    fi
fi

new_fp=$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | cut -d= -f2)

# --- install ----------------------------------------------------------------
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_cert="${DEST_CERT}.prev"
backup_key="${DEST_KEY}.prev"

install_file() {
    local source=$1 destination=$2 mode=$3
    local temporary
    temporary=$(mktemp "${destination}.new.XXXXXX")
    cat "$source" > "$temporary"
    chmod "$mode" "$temporary"
    if [ "$(id -u)" = "0" ]; then
        chown "${USER_NAME}:${GROUP_NAME}" "$temporary" 2>/dev/null ||
            note "could not chown $temporary to ${USER_NAME}:${GROUP_NAME}"
    fi
    mv -f "$temporary" "$destination"
}

if [ -e "$DEST_CERT" ]; then cp -p "$DEST_CERT" "$backup_cert"; fi
if [ -e "$DEST_KEY" ]; then cp -p "$DEST_KEY" "$backup_key"; fi

install_file "$CERT" "$DEST_CERT" 0644
install_file "$KEY" "$DEST_KEY" 0600
note "installed $DEST_CERT ($new_fp) and $DEST_KEY; previous material kept as .prev"

if [ "$VERIFY" = "0" ]; then
    note "verification skipped (--no-verify); the listener still needs a reload"
    exit 0
fi

# --- reload -----------------------------------------------------------------
reload() {
    if [ -n "$UNIT" ]; then
        systemctl kill --signal=HUP "$UNIT"
    else
        local pid
        pid=$(cat "$PIDFILE")
        kill -HUP "$pid"
    fi
}

restore() {
    note "rolling back to the previous certificate"
    [ -e "$backup_cert" ] && cp -p "$backup_cert" "$DEST_CERT"
    [ -e "$backup_key" ] && cp -p "$backup_key" "$DEST_KEY"
    reload || true
}

reload || { restore; die "reload signal failed"; }

# --- verify -----------------------------------------------------------------
# The listener address comes from the same policy: bind and the TLS flag decide whether there is a
# handshake to inspect at all.
if [ -n "$UNIT" ] || [ -n "$PIDFILE" ]; then
    if grep -qE '^[[:space:]]*tls_cert[[:space:]]*=' "$POLICY" 2>/dev/null; then
        bind=$(grep -E '^[[:space:]]*bind[[:space:]]*=' "$POLICY" | head -1 |
               sed -E 's/^[^=]*=[[:space:]]*"([^"]*)".*$/\1/')
        host=${bind%:*}
        port=${bind##*:}
        case "$host" in
            0.0.0.0|"") host=127.0.0.1 ;;
            ::|"[::]") host=::1 ;;
        esac
        served=""
        for _ in $(seq 1 20); do
            served=$(openssl s_client -connect "${host}:${port}" -servername "$host" \
                        -verify_quiet </dev/null 2>/dev/null |
                      openssl x509 -noout -fingerprint -sha256 2>/dev/null |
                      cut -d= -f2 || true)
            [ "$served" = "$new_fp" ] && break
            sleep 0.25
        done
        if [ "$served" != "$new_fp" ]; then
            note "listener at ${host}:${port} is serving ${served:-nothing}, expected $new_fp"
            restore
            die "reload did not take effect; previous certificate restored"
        fi
        note "verified: ${host}:${port} now serves $new_fp"
    else
        note "policy declares no TLS listener; nothing to verify"
    fi
fi

# Only prune after the new material is proven to be in service, so a failed attempt still has its
# rollback copy.
rm -f "$backup_cert" "$backup_key" 2>/dev/null || true
note "done (${stamp})"
