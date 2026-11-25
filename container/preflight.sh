#!/usr/bin/env bash
# container/preflight.sh - V3 preflight for the Stage 3 canary.
#
# Runs on the target host before a container is started or recreated. Every check is a hard
# failure with a diagnostic, because the failure mode this exists to prevent is a container that
# starts successfully and is quietly wrong: an empty site off a typo'd mount, a relabelled host
# tree the project never owned, or enforcement weakened on an Enforcing host while the project
# configuration says SELinux is not being integrated.
#
# Usage: container/preflight.sh [--config PATH] [--compose PATH] [--skip-runtime]
set -euo pipefail

CONFIG="container/config.yaml"
COMPOSE="container/compose.yaml"
SKIP_RUNTIME=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config) CONFIG="$2"; shift 2 ;;
        --compose) COMPOSE="$2"; shift 2 ;;
        --skip-runtime) SKIP_RUNTIME=1; shift ;;
        *) echo "preflight: unknown argument $1" >&2; exit 64 ;;
    esac
done

FAILURES=0
fail() { echo "FAIL $*" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "ok   $*"; }

[[ -f "$CONFIG" ]] || { echo "preflight: no configuration at $CONFIG" >&2; exit 1; }

# Read the handful of scalar values the checks need straight from the project configuration, so
# the checks are against the reviewed source rather than against a rendering of it.
eval "$(python3 - "$CONFIG" <<'PY'
import json, sys, yaml
cfg = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
print("TARGET_HOSTNAME=" + json.dumps(cfg["target"]["hostname"]))
print("TARGET_SELINUX_OBSERVED=" + json.dumps(cfg["target"]["selinux_mode_observed"]))
print("SELINUX_ENABLED=" + json.dumps(str(cfg["security"]["selinux"]["enabled"]).lower()))
print("RUNTIME_NAME=" + json.dumps(cfg["runtime"]["name"]))
print("RUNTIME_VERSION=" + json.dumps(str(cfg["runtime"]["version"])))
print("HOST_PORT=" + json.dumps(str(cfg["publish"][0]["host_port"])))
print("PUBLISH_ADDRESS=" + json.dumps(cfg["publish"][0]["address"]))
print("MOUNT_SOURCES=" + json.dumps(" ".join(
    [m["source"] for m in cfg.get("mounts", [])] + [m["source"] for m in cfg.get("extra_readonly_files", [])])))
PY
)"

echo "preflight: target=$TARGET_HOSTNAME config=$CONFIG"

# --- 1. SELinux mode versus the project toggle (the V3 requirement) --------------------------
HOST_SELINUX="Disabled"
if command -v getenforce >/dev/null 2>&1; then
    HOST_SELINUX="$(getenforce 2>/dev/null || echo Disabled)"
fi

if [[ "$SELINUX_ENABLED" == "false" && "$HOST_SELINUX" == "Enforcing" ]]; then
    # This is the case the brief calls out: a project that performs no SELinux integration must
    # not be run on an Enforcing host, because the container would either fail in ways an operator
    # fixes by relabelling (changing host state the project does not own) or be started with
    # labeling disabled, silently weakening the host's own policy for this workload.
    fail "host SELinux is Enforcing while security.selinux.enabled is false. Either set the
  project toggle to true (and accept project-managed labels), move the canary to a permissive
  host, or stop the canary. The project will not silently weaken enforcement."
elif [[ "$SELINUX_ENABLED" == "false" ]]; then
    pass "host SELinux is $HOST_SELINUX and the project performs no SELinux integration"
else
    if [[ "$HOST_SELINUX" == "Enforcing" ]]; then
        pass "host SELinux is Enforcing and the project toggle is true (project-managed labels)"
    else
        fail "security.selinux.enabled is true but the host is $HOST_SELINUX; labels would be
  accepted by the runtime and ignored by the kernel, which is a configuration that looks
  configured and does nothing"
    fi
fi

# The recorded value must still describe the host being used, or the audit is stale.
if [[ "${HOSTNAME:-}" == "$TARGET_HOSTNAME" || "${HOSTNAME:-}" == "${TARGET_HOSTNAME%%.*}" ]]; then
    pass "running on the configured target host"
else
    fail "running on '${HOSTNAME:-unknown}' but the configuration targets $TARGET_HOSTNAME"
fi

# --- 2. Runtime presence and version -----------------------------------------------------------
if [[ "$SKIP_RUNTIME" -eq 1 ]]; then
    pass "runtime check skipped (--skip-runtime)"
elif command -v "$RUNTIME_NAME" >/dev/null 2>&1; then
    INSTALLED="$("$RUNTIME_NAME" --version 2>/dev/null | head -n1)"
    if [[ "$INSTALLED" == *"$RUNTIME_VERSION"* ]]; then
        pass "runtime $INSTALLED matches the configured $RUNTIME_NAME $RUNTIME_VERSION"
    else
        fail "runtime is '$INSTALLED' but the configuration pins $RUNTIME_NAME $RUNTIME_VERSION"
    fi
else
    fail "configured runtime '$RUNTIME_NAME' is not installed"
fi

# --- 3. Every mount source must already exist ---------------------------------------------------
# `create_host_path: false` makes a missing source fatal at create time; catching it here turns a
# confusing runtime error into a named missing path, and it catches the case the runtime would
# happily create: a bind source that is a *file* the operator expected to be a directory, or vice
# versa.
for src in $MOUNT_SOURCES; do
    if [[ -e "$src" ]]; then
        pass "mount source exists: $src"
    else
        fail "mount source missing: $src (create_host_path is false, so this is fatal)"
    fi
done

# --- 4. The published port must be free, or held by the container this deploy recreates --------
# The first version failed whenever anything held the port, which included the running canary on the
# normal re-deploy path: the documented sequence is preflight then `up -d --force-recreate`, so the
# gate rejected every second deployment. The port is now acceptable when the holder is provably this
# project's own container, and still a hard failure for anything else.
LISTEN="$(ss -Hln "sport = :$HOST_PORT" 2>/dev/null | head -n1 || true)"
CONTAINER_NAME="$(grep -m1 -E '^[[:space:]]*container_name:' "$COMPOSE" 2>/dev/null | awk '{print $2}' || true)"
if [[ -z "$LISTEN" ]]; then
    pass "port $HOST_PORT is free"
elif [[ -n "$CONTAINER_NAME" ]] && command -v "$RUNTIME_NAME" >/dev/null 2>&1 \
        && "$RUNTIME_NAME" ps --format '{{.Names}}|{{.Ports}}' 2>/dev/null \
             | grep -q "^${CONTAINER_NAME}|.*:${HOST_PORT}->"; then
    pass "port $HOST_PORT is held by ${CONTAINER_NAME}, the container this deploy recreates"
else
    fail "port $HOST_PORT is already in use: $LISTEN"
fi

# --- 5. The generated artifact must match the configuration ------------------------------------
if [[ -f "$COMPOSE" ]]; then
    if grep -q ":z\b\|:Z\b" "$COMPOSE" && [[ "$SELINUX_ENABLED" == "false" ]]; then
        fail "generated artifact contains an SELinux mount suffix while the toggle is false"
    else
        pass "generated artifact contains no SELinux relabelling directives"
    fi
    for word in chcon restorecon setsebool; do
        if grep -q "$word" "$COMPOSE"; then
            fail "generated artifact invokes $word; the project never relabels host content"
        fi
    done
    # Compare the artifact's recorded source hash with the hash of the configuration on disk. This
    # is deliberately not a re-render: the target's interpreter and PyYAML are older than the
    # project's build venv (EL8 ships 3.6.8 with PyYAML 3.12, the venv pins 6.0.3), and a
    # re-render here would compare two renderers rather than answer the question that matters -
    # whether this artifact came from this configuration.
    RECORD="$(sed -n 's/^# Source: container\/config\.yaml (sha256 \([0-9a-f]*\)).*/\1/p' "$COMPOSE" | head -n1)"
    ACTUAL="$(python3 - "$CONFIG" <<'PYCFG'
import hashlib, json, sys, yaml
cfg = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
print(hashlib.sha256(json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest())
PYCFG
)"
    if [[ -n "$RECORD" && "$RECORD" == "$ACTUAL" ]]; then
        pass "generated artifact was rendered from this configuration (sha256 ${ACTUAL:0:12})"
    else
        fail "generated artifact is stale: recorded ${RECORD:-none}, configuration hashes to $ACTUAL"
    fi
else
    fail "no generated compose artifact at $COMPOSE"
fi

# --- 6. Host must not be mutated by this run -----------------------------------------------------
# Recorded before/after so a caller can prove the host SELinux state and file contexts were
# untouched; the value itself is only read here.
echo "note host-selinux-before=$HOST_SELINUX"

if [[ "$FAILURES" -gt 0 ]]; then
    echo "preflight: $FAILURES check(s) failed" >&2
    exit 1
fi
echo "preflight: all checks passed"
