#!/usr/bin/env bash
# tests/container/test_rollback.sh - Bundle W6: prove the canary rollback actually works.
#
# W6 asks for a *tested* rollback, not a written one. For the canary the rollback is: remove the
# container, prove nothing about the native service changed, then bring the container back from the
# same artifact and prove it serves again. Each step is asserted here, because the failure mode worth
# preventing is a rollback that appears to succeed while leaving the site broken or the host tree
# altered.
#
# Usage: tests/container/test_rollback.sh [host] [ssh-user]
set -uo pipefail

HOST="${1:-lab-web01.lab}"
USER_SSH="${2:-agent}"
STAGE="/opt/fleet-filter-container"
CONTAINER="fleet-filter-apache-lab-web01"
DOCROOT="/var/www/html"

PASS=0; FAIL=0
ok() { echo "ok   $*"; PASS=$((PASS + 1)); }
bad() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
rsh() { timeout 200 ssh -o BatchMode=yes -o ConnectTimeout=10 "$USER_SSH@$HOST" "sudo -n bash -s" <<<"$1" 2>&1; }

echo "rollback test on $HOST"

native_before="$(rsh "curl -s --max-time 10 -H 'Host: lab-web01.lab' http://127.0.0.1/ai.html | md5sum | cut -d' ' -f1")"
tree_before="$(rsh "find $DOCROOT -printf '%y %u %g %s %p\n' | sort | md5sum | cut -d' ' -f1")"
image_before="$(rsh "podman inspect -f '{{.Image}}' $CONTAINER")"
if [[ -z "$native_before" || -z "$image_before" ]]; then
    echo "cannot read the native response or the container image; refusing to roll back blind" >&2
    exit 1
fi
ok "pre-rollback state captured (native /ai.html md5 ${native_before:0:12}, image ${image_before:0:12})"

# --- 1. stop and remove the container ---------------------------------------------------------------
if rsh "cd $STAGE && podman-compose -f container/compose.yaml down --timeout 10 >/dev/null 2>&1" && ! rsh "podman ps -q -f name=$CONTAINER" | grep -q .; then
    ok "container stopped and removed via the compose artifact"
else
    bad "container still present after compose down"
fi

# --- 2. the native service must be untouched by the removal -----------------------------------------
native_after="$(rsh "curl -s --max-time 10 -H 'Host: lab-web01.lab' http://127.0.0.1/ai.html | md5sum | cut -d' ' -f1")"
tree_after="$(rsh "find $DOCROOT -printf '%y %u %g %s %p\n' | sort | md5sum | cut -d' ' -f1")"
if [[ "$native_after" == "$native_before" ]]; then
    ok "native :80 still serves the identical document with the container gone"
else
    bad "native response changed when the container was removed ($native_before -> $native_after)"
fi
if [[ "$tree_after" == "$tree_before" ]]; then
    ok "host docroot unchanged by the container lifecycle (no ownership, content, or path drift)"
else
    bad "host docroot changed during the rollback ($tree_before -> $tree_after)"
fi

# --- 3. bring it back from the same artifact -----------------------------------------------------------
if rsh "cd $STAGE && podman-compose -f container/compose.yaml up -d >/dev/null 2>&1"; then
    sleep 5
    image_new="$(rsh "podman inspect -f '{{.Image}}' $CONTAINER 2>/dev/null")"
    served="$(rsh "curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:18080/ai.html")"
    if [[ "$image_new" == "$image_before" && "$served" == "200" ]]; then
        ok "recreated from the same image ($image_new) and serving 200 again - rollback is reversible"
    else
        bad "recreate produced image=${image_new:-none} (expected $image_before), canary http=$served"
    fi
else
    bad "compose up failed after the rollback"
fi

echo "rollback tests: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
