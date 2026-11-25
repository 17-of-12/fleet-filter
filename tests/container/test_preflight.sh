#!/usr/bin/env bash
# tests/container/test_preflight.sh - exercise every SELinux branch of container/preflight.sh.
#
# V3 asks for the preflight to fail when the host is Enforcing while the project declares no
# SELinux integration. lab-web01 is Permissive and build01 is Disabled, so the only way to observe
# that branch - and the other three - without waiting for an Enforcing host is to run the preflight
# against a `getenforce` shim and a generated configuration. That also turns the rest of the
# script's logic (hostname match, artifact freshness) into asserted behaviour instead of a script
# that is only ever run in the one configuration that happens to pass.
#
# Usage: tests/container/test_preflight.sh [path/to/repo]
# Exit: 0 when every case behaves as specified, 1 otherwise.
set -uo pipefail

REPO="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
PREFLIGHT="$REPO/container/preflight.sh"
RENDERER="$REPO/bin/render-container-compose.py"
BASE_CONFIG="$REPO/container/config.yaml"

# The repo's own venv is the reviewed renderer; fall back to the system interpreter so the test
# still runs on a target host that has no venv (lab-web01 renders with python3.6 + PyYAML 3.12).
if [[ -x "$REPO/.venv/bin/python" ]]; then PY="$REPO/.venv/bin/python"; else PY="$(command -v python3)"; fi

PASS=0
FAIL=0
ok() { echo "ok   $*"; PASS=$((PASS + 1)); }
bad() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

[[ -f "$PREFLIGHT" ]] || { echo "no preflight at $PREFLIGHT" >&2; exit 1; }
[[ -f "$RENDERER" ]] || { echo "no renderer at $RENDERER" >&2; exit 1; }
[[ -f "$BASE_CONFIG" ]] || { echo "no config at $BASE_CONFIG" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A port the case will publish, chosen free so the preflight's port check is not the thing under
# test. The canary itself normally holds 18080, which would otherwise fail every case.
free_port() {
    for p in 18099 18100 18101 18102 18103; do
        if ! ss -Hln "sport = :$p" 2>/dev/null | grep -q .; then echo "$p"; return; fi
    done
    echo ""
}
PORT="$(free_port)"
[[ -n "$PORT" ]] || { echo "no free test port available" >&2; exit 1; }

# make_case DIR MODE ENABLED - write a config derived from the project config, keeping the target
# identity and security block, and render its compose artifact. Mounts are emptied so the case does
# not depend on the docroot layout of whichever host runs the test; the mount-existence logic is
# covered by the deployed pair on the target.
make_case() {
    local dir="$1" mode="$2" enabled="$3"
    mkdir -p "$dir"
    "$PY" - "$BASE_CONFIG" "$dir/config.yaml" "$mode" "$enabled" "$PORT" <<'PY'
import sys, yaml
src, dst, mode, enabled = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "true"
cfg = yaml.safe_load(open(src, encoding="utf-8"))
cfg["target"]["hostname"] = __import__("socket").gethostname()
cfg["target"]["selinux_mode_observed"] = mode.lower()
cfg["security"]["selinux"]["enabled"] = enabled
cfg["publish"] = [{"scheme": "http", "address": "127.0.0.1", "host_port": int(sys.argv[5]), "container_port": 8080}]
cfg["mounts"] = []
cfg["extra_readonly_files"] = []
open(dst, "w", encoding="utf-8").write(yaml.safe_dump(cfg, default_flow_style=False, sort_keys=True))
PY
    "$PY" "$RENDERER" --config "$dir/config.yaml" --output "$dir/compose.yaml" >/dev/null
}

# run_case DIR MODE - run the preflight with getenforce reporting MODE.
run_case() {
    local dir="$1" mode="$2"
    mkdir -p "$dir/bin"
    printf '#!/bin/sh\necho %s\n' "$mode" > "$dir/bin/getenforce"
    chmod 755 "$dir/bin/getenforce"
    PATH="$dir/bin:$PATH" bash "$PREFLIGHT" --config "$dir/config.yaml" --compose "$dir/compose.yaml" \
        --skip-runtime > "$dir/out" 2> "$dir/err"
    echo "$?" > "$dir/rc"
}

# --- 1. toggle false + host Enforcing: the V3 requirement, must fail ---------------------------
D="$WORK/false-enforcing"; make_case "$D" Enforcing false; run_case "$D" Enforcing
if [[ "$(cat "$D/rc")" == "1" ]] && grep -q "host SELinux is Enforcing while security.selinux.enabled is false" "$D/err"; then
    ok "toggle=false on an Enforcing host fails with the documented diagnostic (V3)"
else
    bad "toggle=false on an Enforcing host should fail; rc=$(cat "$D/rc") err=$(head -c 200 "$D/err")"
fi

# --- 2. toggle false + host Permissive: the shipped configuration, must pass --------------------
D="$WORK/false-permissive"; make_case "$D" Permissive false; run_case "$D" Permissive
if [[ "$(cat "$D/rc")" == "0" ]] && grep -q "preflight: all checks passed" "$D/out"; then
    ok "toggle=false on a Permissive host passes every check"
else
    bad "toggle=false on a Permissive host should pass; rc=$(cat "$D/rc") out=$(head -c 200 "$D/out") err=$(head -c 200 "$D/err")"
fi

# --- 3. toggle true + host Enforcing: project-managed labels, must pass -------------------------
D="$WORK/true-enforcing"; make_case "$D" Enforcing true; run_case "$D" Enforcing
if [[ "$(cat "$D/rc")" == "0" ]] && grep -q "host SELinux is Enforcing and the project toggle is true" "$D/out"; then
    ok "toggle=true on an Enforcing host passes (project-managed labels)"
else
    bad "toggle=true on an Enforcing host should pass; rc=$(cat "$D/rc") out=$(head -c 200 "$D/out")"
fi

# --- 4. toggle true + host Permissive: configured but inert, must fail --------------------------
D="$WORK/true-permissive"; make_case "$D" Permissive true; run_case "$D" Permissive
if [[ "$(cat "$D/rc")" == "1" ]] && grep -q "looks" "$D/err" && grep -q "security.selinux.enabled is true but the host is Permissive" "$D/err"; then
    ok "toggle=true on a Permissive host fails: labels would be accepted and ignored"
else
    bad "toggle=true on a Permissive host should fail; rc=$(cat "$D/rc") err=$(head -c 200 "$D/err")"
fi

# --- 5. toggle false + host Disabled: the build01.lab case, must pass ------------------
D="$WORK/false-disabled"; make_case "$D" Disabled false; run_case "$D" Disabled
if [[ "$(cat "$D/rc")" == "0" ]]; then
    ok "toggle=false on a Disabled host passes"
else
    bad "toggle=false on a Disabled host should pass; rc=$(cat "$D/rc") err=$(head -c 200 "$D/err")"
fi

# --- 6. stale artifact: the compose must be the rendering of the config it sits beside ----------
D="$WORK/stale"; make_case "$D" Permissive false
# The artifact hash covers the parsed configuration, so a comment edit is invisible by design;
# drift has to be structural. `target.observed_on` is the cheapest field that changes the parse
# without changing anything else the preflight checks.
"$PY" - "$D/config.yaml" <<'PYCFG'
import sys, yaml
p = sys.argv[1]
cfg = yaml.safe_load(open(p, encoding="utf-8"))
cfg["target"]["observed_on"] = "1999-01-01"
open(p, "w", encoding="utf-8").write(yaml.safe_dump(cfg, default_flow_style=False, sort_keys=True))
PYCFG
run_case "$D" Permissive
if [[ "$(cat "$D/rc")" == "1" ]] && grep -q "generated artifact is stale" "$D/err"; then
    ok "a compose artifact that is not the current rendering of its config is reported stale"
else
    bad "stale artifact should fail; rc=$(cat "$D/rc") err=$(head -c 200 "$D/err")"
fi

# --- 7. wrong host: the preflight must refuse to vet the wrong machine --------------------------
D="$WORK/otherhost"; mkdir -p "$D"
"$PY" - "$BASE_CONFIG" "$D/config.yaml" <<'PY'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
cfg["target"]["hostname"] = "not-the-configured-target.example.edu"
open(sys.argv[2], "w", encoding="utf-8").write(yaml.safe_dump(cfg, default_flow_style=False, sort_keys=True))
PY
"$PY" "$RENDERER" --config "$D/config.yaml" --output "$D/compose.yaml" >/dev/null
run_case "$D" Permissive
if [[ "$(cat "$D/rc")" == "1" ]] && grep -q "but the configuration targets" "$D/err"; then
    ok "running on a host other than the configured target fails rather than vetting the wrong box"
else
    bad "wrong-host case should fail; rc=$(cat "$D/rc") err=$(head -c 200 "$D/err")"
fi

echo "preflight tests: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
