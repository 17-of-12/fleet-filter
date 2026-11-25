#!/usr/bin/env bash
# tests/container/test_containment.sh - Bundle W1/W2 evidence for the Stage 3 canary.
#
# W1 asks whether a normal developer edit on the host changes what the container serves, with no
# image rebuild, no copy, and no ownership change. W2 asks whether the read-only mount contract is
# actually enforced - the container must not be able to modify host source, while the enumerated
# writable mounts must be writable. Both questions are answerable only against a running canary,
# and both are the claims Stage 3 rests on, so they are asserted here rather than believed.
#
# The test is deliberately additive: it writes one scratch file into the docroot, proves it is
# served, removes it, and proves the host tree is byte-identical to the snapshot it took first.
# Nothing else on the host is touched.
#
# Usage: tests/container/test_containment.sh [host] [ssh-user]
#   Runs over ssh against the canary host (default lab-web01.lab, agent).
set -uo pipefail

HOST="${1:-lab-web01.lab}"
USER_SSH="${2:-agent}"
STAGE="/opt/fleet-filter-container"
CONTAINER="fleet-filter-apache-lab-web01"
URL="http://127.0.0.1:18080"
DOCROOT="/var/www/html"
LOGDIR="/var/log/fleet-filter-canary"

PASS=0
FAIL=0
ok() { echo "ok   $*"; PASS=$((PASS + 1)); }
bad() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
# Commands are piped in over stdin rather than quoted into the ssh command line: the checks
# themselves contain quotes and redirections, and nesting them inside `bash -c '...'` is how a
# test starts failing on quoting instead of on the thing it is supposed to be checking.
rsh() { timeout 120 ssh -o BatchMode=yes -o ConnectTimeout=10 "$USER_SSH@$HOST" "sudo -n bash -s" <<<"$1" 2>&1; }
# cexec runs a command *inside the canary*, which is the whole point of a containment test: running
# it on the host tests the host's permissions, not the container's, and the host answers "writable"
# for paths the container sees as read-only.
cexec() { rsh "podman exec $CONTAINER sh -c \"$1\""; }

echo "containment tests against $HOST ($CONTAINER)"

# --- preconditions ------------------------------------------------------------------------------
if ! rsh "command -v podman" | grep -q podman; then
    echo "cannot reach $HOST over ssh, or podman is missing" >&2
    exit 1
fi
# `podman exists` is newer than the pinned 4.9.4, so existence and state both come from inspect -
# and asking one question per call keeps the failure message honest about which one failed.
if ! rsh "podman inspect $CONTAINER" | grep -q '"Id"'; then
    echo "container $CONTAINER does not exist on $HOST" >&2
    exit 1
fi
if ! rsh "podman inspect -f '{{.State.Running}}' $CONTAINER" | grep -q true; then
    echo "container $CONTAINER exists but is not running" >&2
    exit 1
fi

# --- W2.1 the docroot must be read-only inside the container ------------------------------------
RO="$(cexec "touch /var/www/html/.fleet-filter-w2 2>&1")"
if echo "$RO" | grep -qi "read-only file system"; then
    ok "W2 writing into the container's /var/www/html fails with 'Read-only file system'"
else
    bad "W2 expected a read-only error writing to /var/www/html, got: $(echo "$RO" | head -c 160)"
fi

# --- W2.2 the baked Apache configuration must not be writable at runtime -------------------------
CFG="$(cexec "touch /etc/httpd/conf/httpd.conf.fleet-filter 2>&1")"
if echo "$CFG" | grep -qi "read-only file system"; then
    ok "W2 the image's /etc/httpd is read-only, so a running container cannot drift its own config"
else
    bad "W2 expected /etc/httpd to be read-only, got: $(echo "$CFG" | head -c 160)"
fi

# --- W2.3 the enumerated writable mounts must actually be writable --------------------------------
LOGW="$(cexec "touch /var/log/httpd/.fleet-filter-w2 2>&1 && ls -ld /var/log/httpd/.fleet-filter-w2 2>&1")"
if echo "$LOGW" | grep -q "^-rw"; then
    ok "W2 the log mount is writable in the container ($LOGW)"
    if rsh "test -e $LOGDIR/.fleet-filter-w2"; then
        ok "W2 the file created inside the container is visible on the host at $LOGDIR (the mount is the host directory, not an anonymous volume)"
    else
        bad "W2 the log file was created in the container but not on the host (mount is not the host directory)"
    fi
    rsh "rm -f $LOGDIR/.fleet-filter-w2"
else
    bad "W2 the log mount should be writable, got: $(echo "$LOGW" | head -c 160)"
fi

SESSW="$(cexec "touch /var/lib/php/session/.fleet-filter-w2 2>&1 >/dev/null; echo rc=\$?; rm -f /var/lib/php/session/.fleet-filter-w2 2>/dev/null")"
if echo "$SESSW" | grep -q "rc=0"; then
    ok "W2 the php session mount is writable (the one path a PHP app legitimately writes to)"
else
    bad "W2 the php session mount should be writable, got: $(echo "$SESSW" | head -c 160)"
fi

# --- W2.4 nothing outside the mount contract may change ------------------------------------------
SNAP="$(rsh "find $DOCROOT -printf '%y %u %g %s %p\n' 2>/dev/null | sort | md5sum | cut -d' ' -f1")"
if [[ -z "$SNAP" ]]; then
    bad "W2 could not snapshot the host docroot"
else
    # --- W1 a developer edit must be served without a rebuild, a copy, or an ownership change ----
    MARKER="fleet-filter-w1-$$"
    WRITE="$(rsh "umask 022; printf 'fleet-filter W1 marker $MARKER\n' > $DOCROOT/$MARKER.html 2>&1; chown --reference=$DOCROOT/index.html $DOCROOT/$MARKER.html 2>/dev/null || true")"
    # Fetched on the target: the canary publishes on the target's own loopback, so a curl from the
    # control node would be testing a port that does not exist there.
    SERVED="$(rsh "curl -s --max-time 10 $URL/$MARKER.html")"
    HOSTED="$(rsh "cat $DOCROOT/$MARKER.html 2>/dev/null")"
    if [[ -n "$WRITE" ]]; then
        bad "W1 could not create the scratch file in the host docroot: $(echo "$WRITE" | head -c 160)"
    elif [[ "$SERVED" == "$HOSTED" && -n "$SERVED" ]]; then
        ok "W1 a file created on the host is served by the running container immediately, no rebuild and no copy"
    else
        bad "W1 served body differs from the host file; served='$SERVED' host='$HOSTED'"
    fi
    rsh "rm -f $DOCROOT/$MARKER.html"

    SNAP_AFTER="$(rsh "find $DOCROOT -printf '%y %u %g %s %p\n' 2>/dev/null | sort | md5sum | cut -d' ' -f1")"
    if [[ "$SNAP_AFTER" == "$SNAP" ]]; then
        ok "W2 after the whole run the host docroot is byte-identical to the pre-run snapshot (owners, sizes, paths)"
    else
        bad "W2 the host docroot changed during the run (before=$SNAP after=$SNAP_AFTER)"
    fi
fi

# --- W2.5 the container must not be able to write executable code into the docroot ----------------
# The attack this checks is the ordinary one: a compromised web process dropping a php file into a
# script-enabled directory. With the docroot read-only, that write cannot happen at all.
PHPW="$(cexec "touch /var/www/html/fleet-filter-shell.php 2>&1; rm -f /var/www/html/fleet-filter-shell.php 2>/dev/null")"
if echo "$PHPW" | grep -qi "read-only file system"; then
    ok "W2 a container-side process cannot drop a php file into the docroot (the usual webshell move)"
else
    bad "W2 expected the php-file write to fail, got: $(echo "$PHPW" | head -c 160)"
fi

# --- W4 containment: processes, /proc masking, privilege, network egress ---------------------------
PIDS="$(cexec "ps -e --no-headers 2>/dev/null | wc -l")"
HOST_PIDS="$(rsh "ps -e --no-headers | wc -l")"
if [[ -n "$PIDS" ]] && (( PIDS < 40 )) && [[ -n "$HOST_PIDS" ]] && (( HOST_PIDS > PIDS )); then
    ok "W4 private PID namespace: the container sees $PIDS processes while the host runs $HOST_PIDS"
else
    bad "W4 process visibility unexpected (container='$PIDS' host='$HOST_PIDS')"
fi

NNP="$(cexec "grep -m1 NoNewPrivs /proc/self/status | tr -cd 0-9")"
if [[ "$NNP" == "1" ]]; then
    ok "W4 NoNewPrivs is active inside the container (setuid binaries cannot escalate)"
else
    bad "W4 expected NoNewPrivs=1 inside the container, got '$NNP'"
fi

KCORE="$(cexec "stat -c %s /proc/kcore 2>&1 | head -1")"
if [[ "$KCORE" == "0" ]]; then
    ok "W4 /proc/kcore is masked (0 bytes), so kernel memory is not readable from the container"
else
    bad "W4 /proc/kcore is not masked (size '$KCORE')"
fi

SYSFS="$(cexec "touch /sys/cgroup.fleet-filter 2>&1 | head -1")"
if echo "$SYSFS" | grep -qiE "read-only|permission denied"; then
    ok "W4 /sys is not writable from the container"
else
    bad "W4 expected /sys to be unwritable, got: $(echo "$SYSFS" | head -c 120)"
fi

# Network egress: what the container can reach determines the blast radius of a compromised
# web process. Tested with a short connect timeout so an unreachable target costs seconds, not a hang.
# curl exists in the image (it is in the recorded SBOM), so reachability is measured with curl's own
# exit code rather than a /dev/tcp redirect that needs another layer of shell quoting to work.
for target in "10.30.72.19:80" "198.51.100.110:8088" "127.0.0.1:8080"; do
    REACH="$(cexec "curl -s -o /dev/null --connect-timeout 5 http://$target/; echo rc=\$?")"
    if echo "$REACH" | grep -q "rc=0"; then
        echo "note egress from container to $target -> reachable"
    else
        echo "note egress from container to $target -> not reachable ($(echo "$REACH" | head -c 80))"
    fi
done
EXT="$(cexec "timeout 6 getent hosts fleet-filter.invalid 2>&1 >/dev/null && echo resolved || echo unresolvable")"
echo "note DNS from container (synthetic name) -> $(echo "$EXT" | tail -1)"

echo "containment tests: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
