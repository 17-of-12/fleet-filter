#!/usr/bin/env bash
# Pull this host's policy from the control node, install it, and prove the gateway took it.
#
# Pull rather than push because the hosts that matter most cannot be dialled: one sits behind a load
# balancer, others are on management networks with no inbound path from the control node. A host that
# fetches its own file works wherever outbound SSH does, and it means a compromised control node
# cannot walk into a host's policy - it can only publish something the host then validates.
#
# The steps are the same shape as the certificate hook, for the same reason:
#
#   1. fetch the policy and its digest, verify the digest's signature, and refuse any mismatch
#      (a truncated file must not be applied, and neither must a well-formed file from a host that
#      is not the one holding the signing key)
#   2. validate with the gateway's own parser before touching the live file - a policy the parser
#      refuses would be a restart loop on a host that has no console
#   3. no-op when the digest is unchanged, so the timer is cheap and the journal stays readable
#   4. install atomically, signal a reload, and then WAIT for the journal to say the new version is
#      in force. A signal is not proof; the reload log line is.
#   5. on any failure, restore the previous policy and reload again, leaving the host exactly as it
#      was rather than half-applied
#
# Usage:
#   policy-fetch.sh --source root@control:/var/lib/fleet-filter/publish --name ff-apache01 \
#                   --dest /etc/fleet-filter/policy.toml --unit fleet-filter-gateway
#
# Environment: PATH is expected to contain the gateway binary; --binary overrides.

set -euo pipefail

SOURCE=""
NAME=$(hostname -s)
DEST="/etc/fleet-filter/policy.toml"
UNIT="fleet-filter-gateway"
PIDFILE=""
LOGFILE=""
BINARY=${GATEWAY_BINARY:-/usr/local/bin/fleet-filter-gateway}
TIMEOUT=15
# Authenticity, not just integrity: the digest arrives from the same host as the policy, so on its
# own it proves the transfer was intact and nothing about who wrote the file. The signature is
# verified against a key this host was given out of band, at install time, by the operator.
SIGNING_KEY="/etc/fleet-filter/policy-signing.pub"
ALLOW_UNSIGNED=0

die() { echo "policy-fetch: $*" >&2; exit 1; }
note() { echo "policy-fetch: $*" >&2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --source) SOURCE=${2:?--source needs a value}; shift 2 ;;
        --name) NAME=${2:?--name needs a value}; shift 2 ;;
        --dest) DEST=${2:?--dest needs a value}; shift 2 ;;
        --unit) UNIT=${2:?--unit needs a value}; shift 2 ;;
        --binary) BINARY=${2:?--binary needs a value}; shift 2 ;;
        --pid) PIDFILE=${2:?--pid needs a value}; shift 2 ;;
        --log) LOGFILE=${2:?--log needs a value}; shift 2 ;;
        --timeout) TIMEOUT=${2:?--timeout needs a value}; shift 2 ;;
        --signing-key) SIGNING_KEY=${2:?--signing-key needs a value}; shift 2 ;;
        --allow-unsigned) ALLOW_UNSIGNED=1; shift ;;
        --help|-h) sed -n '3,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$SOURCE" ] || die "--source is required (user@host:/path or a local directory)"
[ -x "$BINARY" ] || die "gateway binary not executable: $BINARY"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() {
    local file=$1 target=$2
    case "$SOURCE" in
        *:*) scp -q -o BatchMode=yes "${SOURCE%/}/$file" "$target" ;;
        *) cp "${SOURCE%/}/$file" "$target" ;;
    esac
}

fetch "$NAME.toml" "$work/policy.toml" || die "could not fetch $NAME.toml from $SOURCE"
fetch "$NAME.sha256" "$work/policy.sha256" || die "could not fetch $NAME.sha256 from $SOURCE"

if [ -f "$SIGNING_KEY" ]; then
    fetch "$NAME.sha256.sig" "$work/policy.sha256.sig" || die "could not fetch $NAME.sha256.sig from $SOURCE"
    openssl dgst -sha256 -verify "$SIGNING_KEY" -signature "$work/policy.sha256.sig" \
        "$work/policy.sha256" >/dev/null 2>&1 ||
        die "the digest is not signed by the policy signing key at $SIGNING_KEY"
elif [ "$ALLOW_UNSIGNED" -eq 1 ]; then
    note "WARNING: $SIGNING_KEY is absent, so this policy is unauthenticated (--allow-unsigned)"
else
    die "no policy signing key at $SIGNING_KEY; install it, or pass --allow-unsigned to accept an unsigned digest"
fi

expected=$(tr -d '[:space:]' < "$work/policy.sha256")
actual=$(sha256sum "$work/policy.toml" | cut -d' ' -f1)
[ "$expected" = "$actual" ] || die "digest mismatch: manifest says ${expected:0:16}, file is ${actual:0:16}"

# The parser is the authority. `--show-policy` exits non-zero on anything it would refuse at startup.
"$BINARY" --policy "$work/policy.toml" --show-policy > "$work/show.txt" 2>"$work/show.err" ||
    die "the gateway refuses this policy: $(head -1 "$work/show.err")"
note "gateway accepts it: $(head -1 "$work/show.txt" | cut -c1-90)"

if [ -f "$DEST" ] && [ "$(sha256sum "$DEST" | cut -d' ' -f1)" = "$actual" ]; then
    note "already current (${actual:0:16}); nothing to do"
    exit 0
fi

backup="$DEST.prev"
if [ -f "$DEST" ]; then cp -p "$DEST" "$backup"; fi

install -m 0644 "$work/policy.toml" "$DEST"
installed=$(sha256sum "$DEST" | cut -d' ' -f1)
[ "$installed" = "$actual" ] || die "install produced ${installed:0:16}, expected ${actual:0:16}"
note "installed ${actual:0:16} into $DEST"

since=$(date '+%Y-%m-%d %H:%M:%S')
reload() {
    if [ -n "$PIDFILE" ]; then
        kill -HUP "$(cat "$PIDFILE")"
    else
        systemctl kill --signal=HUP "$UNIT"
    fi
}

# systemd keeps the reload line in the journal; a process started by hand keeps it where its stdout
# was redirected. Both are the same evidence, so the check reads whichever applies.
reload_evidence() {
    if [ -n "$LOGFILE" ]; then
        [ -f "$LOGFILE" ] && tail -50 "$LOGFILE" | grep -E "policy reload (ok|: unchanged)" | tail -1
    else
        journalctl -u "$UNIT" --since "$since" --no-pager -o cat 2>/dev/null |
            grep -E "policy reload (ok|: unchanged)" | tail -1
    fi
}

restore() {
    note "rolling back to the previous policy"
    if [ -f "$backup" ]; then
        cp -p "$backup" "$DEST"
        reload || true
    fi
}

reload || { restore; die "reload signal failed"; }

# The journal line is the proof. The gateway prints either "policy reload ok" (with the new version)
# or "policy reload: unchanged" - and the second one after an install means the process is not
# reading the file that was written, which is worth failing on rather than discovering later.
deadline=$((SECONDS + TIMEOUT))
confirmed=""
while [ $SECONDS -lt $deadline ]; do
    line=$(reload_evidence || true)
    case "$line" in
        *"policy reload ok"*)
            # Match on the digest fragment so a reload of some other file cannot satisfy this.
            case "$line" in
                *"${actual:0:16}"*) confirmed="$line" ;;
            esac
            ;;
    esac
    [ -n "$confirmed" ] && break
    sleep 1
done

if [ -z "$confirmed" ]; then
    note "no reload confirmation in the journal within ${TIMEOUT}s; last line: ${line:-none}"
    restore
    die "reload did not take effect; previous policy restored"
fi

note "confirmed: $(echo "$confirmed" | cut -c1-120)"
rm -f "$backup" 2>/dev/null || true
