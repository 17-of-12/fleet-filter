#!/usr/bin/env bash
# bin/rebuild-gateway.sh - Bundle N6: rebuild the gateway when its source changed, otherwise no-op.
#
# N6 asks for "timer or CI that rebuilds on dependency change and emits a new versioned artifact",
# which is a question about state, not about time: has the source that produces the artifact changed
# since the last artifact was built? Answering it from `git rev-parse HEAD` is not enough, because an
# uncommitted edit - the most common reason to want a rebuild - does not move HEAD. So the decision is
# made from a content fingerprint of the gateway tree (bin/gateway-source-fingerprint.py), which
# bin/build-gateway.sh records inside every artifact record.
#
# The check is deliberately three-way rather than a yes/no:
#   up-to-date    an artifact exists for this fingerprint and dist/ holds a binary with the hash that
#                 artifact recorded - nothing to do, and the strongest answer the repo can give
#   stale         an artifact exists for this fingerprint but dist/ is missing or holds a different
#                 hash - the record and the tree disagree, so rebuild rather than trust the record
#   rebuild       no artifact exists for this fingerprint
#
# A rebuild that fails must not be recorded as a success, so the exit status is the build's own and
# the log line records the failure too.
#
# Usage: bin/rebuild-gateway.sh [--dry-run] [--force] [--json] [--no-log]
#   --dry-run  report the decision without building
#   --force    rebuild even when the fingerprint matches an existing artifact
#   --json     emit the decision as JSON (for CI and for the systemd service's journal)
#   --no-log   do not append to data/artifacts/rebuild-log.tsv
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATEWAY_DIR="${REPO_ROOT}/gateway"
ARTIFACTS_DIR="${REPO_ROOT}/data/artifacts"
DIST_BIN="${REPO_ROOT}/dist/fleet-filter-gateway"
LOG="${ARTIFACTS_DIR}/rebuild-log.tsv"

DRY_RUN=0
FORCE=0
AS_JSON=0
WRITE_LOG=1
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --force)   FORCE=1 ;;
        --json)    AS_JSON=1 ;;
        --no-log)  WRITE_LOG=0 ;;
        -h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

emit() {
    if [[ "$AS_JSON" -eq 1 ]]; then
        printf '{"fingerprint":"%s","decision":"%s","artifact":"%s"}\n' "$FINGERPRINT" "$1" "${2:-}"
    else
        printf '%s %s%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "${2:+ $2}"
    fi
}

log_line() {
    [[ "$WRITE_LOG" -eq 1 ]] || return 0
    printf '%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$FINGERPRINT" "${2:-}" >> "$LOG"
}

[[ -d "$GATEWAY_DIR" ]] || { echo "error: $GATEWAY_DIR does not exist" >&2; exit 1; }
FINGERPRINT="$("${REPO_ROOT}/bin/gateway-source-fingerprint.py" "$GATEWAY_DIR")" || {
    echo "error: cannot fingerprint the gateway source" >&2; exit 1; }

# Find an artifact record that was built from exactly this source.
MATCH="$(grep -l "\"source_sha256\": \"${FINGERPRINT}\"" "${ARTIFACTS_DIR}"/fleet-filter-gateway-*.json 2>/dev/null | head -1 || true)"

decision=""
if [[ "$FORCE" -eq 1 ]]; then
    decision="force"
elif [[ -n "$MATCH" ]]; then
    recorded="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("sha256",""))' "$MATCH" 2>/dev/null || echo "")"
    actual=""
    [[ -f "$DIST_BIN" ]] && actual="$(sha256sum "$DIST_BIN" | cut -d' ' -f1)"
    if [[ -n "$recorded" && "$recorded" == "$actual" ]]; then
        decision="up-to-date"
    else
        # The record exists but dist/ does not match it: a missing or replaced binary. Rebuilding is
        # safer than trusting a record whose artifact is not where the record says it is.
        decision="stale"
    fi
else
    decision="rebuild"
fi

if [[ "$decision" == "up-to-date" && "$FORCE" -ne 1 ]]; then
    emit "up-to-date" "$MATCH"
    log_line "skip" "$MATCH"
    exit 0
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    emit "$decision" "$MATCH"
    exit 0
fi

emit "building" "$MATCH"
if "${REPO_ROOT}/bin/build-gateway.sh" >"${ARTIFACTS_DIR}/rebuild-last-build.log" 2>&1; then
    new_record="$(ls -t "${ARTIFACTS_DIR}"/fleet-filter-gateway-*.json 2>/dev/null | head -1)"
    emit "built" "$new_record"
    log_line "built" "$new_record"
else
    rc=$?
    emit "build-failed" "$MATCH"
    log_line "build-failed" "$MATCH"
    echo "build failed; see ${ARTIFACTS_DIR}/rebuild-last-build.log" >&2
    exit "$rc"
fi
