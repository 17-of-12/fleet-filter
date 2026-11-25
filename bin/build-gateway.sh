#!/bin/bash
# build-gateway.sh - Bundle N build pipeline for fleet-filter-gateway.
#
# Purpose
# -------
# Produce a versioned gateway artifact from a reproducible EL8 build and record its provenance
# (git commit, toolchain, sha256, lockfile hash) in `data/artifacts/`. N3 requires the artifact
# to be *executed* on EL8 and EL9, so this script's output is a file plus a record, not just a
# built image - the record is what lets a later run answer "which commit produced this binary".
#
# Design notes
# ------------
# * The build runs in `podman build FROM oraclelinux:8` rather than natively on the caller, so
#   the compiler and glibc are pinned by the image and not by whatever the host happens to have.
#   lab-web01 (the EL8 test target) has no container runtime, and build01 (which does) is EL9 -
#   building natively on build01 would link against glibc 2.34 and could not run on EL8.
# * `set -euo pipefail` plus an explicit `--timeout` on the podman invocation: a build that
#   hangs must fail loudly rather than leave a caller guessing (project rule from the
#   measure-request-cost.sh incident, where an unbounded command ran 20 minutes).
# * Re-running is safe: the image tag is derived from the git commit, and the artifact is
#   overwritten only after the new binary's `--version` check succeeds.
# * `bin/check.sh --rust` runs first (operating rule 15) so an artifact record can never describe
#   a tree that fails formatting, lints, or unit tests. The container build also lints internally
#   (see gateway/Containerfile `ARG LINT`); running the native check first is what makes the
#   failure fast instead of surfacing it three minutes into a podman build.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATEWAY_DIR="${REPO_ROOT}/gateway"
DIST_DIR="${REPO_ROOT}/dist"
ARTIFACTS_DIR="${REPO_ROOT}/data/artifacts"
IMAGE_REPO="localhost/fleet-filter-gateway"
BUILD_TIMEOUT="${BUILD_TIMEOUT:-3600}"
PULL_POLICY="${PULL_POLICY:-missing}"

usage() {
    cat <<'USAGE'
usage: build-gateway.sh [--image-only] [--skip-build] [--skip-check]

  --image-only   build the image but do not extract or record an artifact
  --skip-build   reuse the existing image tag and only re-extract/record the artifact
  --skip-check   do not run bin/check.sh --rust first (only for building a known-dirty tree)

environment:
  BUILD_TIMEOUT   seconds to allow the podman build (default 3600)
  PULL_POLICY     podman pull policy: missing|always|never|newer (default missing)
  PODMAN          podman binary (default: sudo podman, falling back to podman)
USAGE
}

IMAGE_ONLY=0
SKIP_BUILD=0
SKIP_CHECK=0
while [ $# -gt 0 ]; do
    case "$1" in
        --image-only) IMAGE_ONLY=1 ;;
        --skip-build) SKIP_BUILD=1 ;;
        --skip-check) SKIP_CHECK=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

[ -d "$GATEWAY_DIR" ] || { echo "error: missing $GATEWAY_DIR" >&2; exit 1; }
[ -f "$GATEWAY_DIR/Cargo.toml" ] || { echo "error: missing $GATEWAY_DIR/Cargo.toml" >&2; exit 1; }

# Podman on build01 is installed but the agent user may need sudo for the root runtime.
PODMAN="${PODMAN:-}"
if [ -z "$PODMAN" ]; then
    if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
        PODMAN="podman"
    elif command -v sudo >/dev/null 2>&1 && sudo -n podman info >/dev/null 2>&1; then
        PODMAN="sudo podman"
    else
        echo "error: no usable podman (neither 'podman info' nor 'sudo -n podman info' succeeded)" >&2
        exit 1
    fi
fi

# Version and provenance inputs are read from the source of truth, not passed in, so a record
# cannot disagree with the tree it was built from.
VERSION="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$GATEWAY_DIR/Cargo.toml" | head -1)"
[ -n "$VERSION" ] || { echo "error: could not read [package].version from Cargo.toml" >&2; exit 1; }
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "uncommitted")"
GIT_SHA7="${GIT_SHA:0:7}"
DIRTY=0
if [ "$GIT_SHA" != "uncommitted" ] && [ -n "$(git -C "$REPO_ROOT" status --porcelain -- gateway 2>/dev/null)" ]; then
    DIRTY=1
fi
TAG="${IMAGE_REPO}:${VERSION}-${GIT_SHA7}"

echo "== build-gateway =="
echo "repo_root:   $REPO_ROOT"
echo "version:     $VERSION"
echo "git commit:  $GIT_SHA (gateway tree dirty: $DIRTY)"
echo "image tag:   $TAG"
echo "podman:      $PODMAN"

# Static gate first: rule 15 makes `bin/check.sh` the command behind "tests must pass before
# deploy" (rule 11). Skipping it is allowed but is announced, so a record built without the gate
# cannot be mistaken for one that passed it.
if [ "$SKIP_BUILD" -eq 0 ] && [ "$SKIP_CHECK" -eq 0 ]; then
    if [ -x "${REPO_ROOT}/bin/check.sh" ]; then
        echo "-- static gate (bin/check.sh --rust) --"
        "${REPO_ROOT}/bin/check.sh" --rust
    else
        echo "warning: ${REPO_ROOT}/bin/check.sh is not executable; the static gate did not run" >&2
    fi
elif [ "$SKIP_BUILD" -eq 0 ]; then
    echo "warning: static gate skipped (--skip-check)" >&2
fi

if [ "$SKIP_BUILD" -eq 0 ]; then
    echo "-- building (timeout ${BUILD_TIMEOUT}s) --"
    # `--pull=${PULL_POLICY}` keeps a repeat build from re-fetching the base image every time
    # while still allowing an intentional refresh.
    timeout "$BUILD_TIMEOUT" $PODMAN build \
        --pull="${PULL_POLICY}" \
        -f "$GATEWAY_DIR/Containerfile" \
        -t "$TAG" \
        "$GATEWAY_DIR"
    # Also tag :latest so a deployment target has a stable reference that still names a version.
    $PODMAN tag "$TAG" "${IMAGE_REPO}:latest" 2>/dev/null || true
fi

if [ "$IMAGE_ONLY" -eq 1 ]; then
    echo "image built: $TAG"
    exit 0
fi

echo "-- extracting artifact --"
mkdir -p "$DIST_DIR" "$ARTIFACTS_DIR"
CID="$($PODMAN create "$TAG")"
trap '$PODMAN rm -f "$CID" >/dev/null 2>&1 || true' EXIT
$PODMAN cp "$CID:/usr/local/bin/fleet-filter-gateway" "${DIST_DIR}/fleet-filter-gateway.new"
chmod 0755 "${DIST_DIR}/fleet-filter-gateway.new"

# The extracted binary is verified before it replaces the previous artifact: an artifact that
# runs and prints its own version is a different claim from one that merely exists.
REPORTED_VERSION="$("${DIST_DIR}/fleet-filter-gateway.new" --version 2>&1 || true)"
EXPECTED_VERSION="fleet-filter-gateway ${VERSION}"
if [ "$REPORTED_VERSION" != "$EXPECTED_VERSION" ]; then
    echo "error: artifact reported '$REPORTED_VERSION', expected '$EXPECTED_VERSION'" >&2
    exit 1
fi
mv "${DIST_DIR}/fleet-filter-gateway.new" "${DIST_DIR}/fleet-filter-gateway"
cp "$DIST_DIR/fleet-filter-gateway" "${DIST_DIR}/fleet-filter-gateway-${VERSION}-${GIT_SHA7}"

# Capture the lockfile the build produced. The runtime image carries it at
# /usr/share/fleet-filter-gateway/Cargo.lock; the builder stage path (/Cargo.lock) is tried as a
# fallback so the script works against either image layout. If the repo already has a lockfile
# and the build produced a different one, that is a real finding and is reported rather than
# silently overwritten.
LOCK_COPIED=0
for lock_path in /usr/share/fleet-filter-gateway/Cargo.lock /Cargo.lock; do
    if $PODMAN cp "$CID:$lock_path" "${DIST_DIR}/Cargo.lock.new" 2>/dev/null; then
        LOCK_COPIED=1
        if [ -f "$GATEWAY_DIR/Cargo.lock" ] && ! cmp -s "${DIST_DIR}/Cargo.lock.new" "$GATEWAY_DIR/Cargo.lock"; then
            echo "note: build produced a Cargo.lock that differs from the committed one (from $lock_path)" >&2
        fi
        if [ ! -f "$GATEWAY_DIR/Cargo.lock" ]; then
            cp "${DIST_DIR}/Cargo.lock.new" "$GATEWAY_DIR/Cargo.lock"
            echo "recorded: gateway/Cargo.lock (from $lock_path)"
        fi
        rm -f "${DIST_DIR}/Cargo.lock.new"
        break
    fi
done
[ "$LOCK_COPIED" -eq 1 ] || echo "warning: no Cargo.lock found in the image; provenance will record none" >&2

SHA256="$(sha256sum "${DIST_DIR}/fleet-filter-gateway" | awk '{print $1}' || true)"
LOCK_SHA="$(sha256sum "$GATEWAY_DIR/Cargo.lock" 2>/dev/null | awk '{print $1}' || true)"
TOOLCHAIN=""
# The toolchain is read back from the image rather than from the host, so the record describes
# the compiler that actually produced the binary (the ADR pins rustc 1.92.0 from the EL8 module;
# this is how that claim is checked instead of asserted).
for tool_path in /usr/share/fleet-filter-gateway/TOOLCHAIN /toolchain.txt; do
    # `podman cp ... -` streams a tar archive, not file contents, so the file is copied to a
    # real path and read from there.
    if $PODMAN cp "$CID:$tool_path" /tmp/gw-toolchain.probe 2>/dev/null; then
        TOOLCHAIN="$(tr -d '\r\n' < /tmp/gw-toolchain.probe 2>/dev/null || true)"
        rm -f /tmp/gw-toolchain.probe
        [ -n "$TOOLCHAIN" ] && break
    fi
done
[ -n "$TOOLCHAIN" ] || TOOLCHAIN="unknown"
IMAGE_ID="$($PODMAN images --format '{{.ID}}' "$TAG" | head -1)"
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# The source fingerprint is what bin/rebuild-gateway.sh uses to decide whether a rebuild is
# needed; recording it here is what makes an existing artifact answer that question.
SOURCE_SHA="$("${REPO_ROOT}/bin/gateway-source-fingerprint.py" "${REPO_ROOT}/gateway" 2>/dev/null || echo unknown)"

RECORD="${ARTIFACTS_DIR}/fleet-filter-gateway-${VERSION}-${GIT_SHA7}.json"
cat > "$RECORD" <<JSON
{
  "artifact": "fleet-filter-gateway",
  "version": "${VERSION}",
  "git_commit": "${GIT_SHA}",
  "gateway_tree_dirty": ${DIRTY},
  "built_at_utc": "${BUILT_AT}",
  "sha256": "${SHA256}",
  "image_tag": "${TAG}",
  "image_id": "${IMAGE_ID}",
  "toolchain": "${TOOLCHAIN}",
  "cargo_lock_sha256": "${LOCK_SHA:-none}",
  "source_sha256": "${SOURCE_SHA}",
  "build_host": "$(hostnamectl --static 2>/dev/null || hostname)",
  "build_method": "podman build FROM oraclelinux:8 (see gateway/Containerfile)"
}
JSON

echo "-- artifact recorded --"
echo "path:   ${DIST_DIR}/fleet-filter-gateway"
echo "sha256: ${SHA256}"
echo "record: ${RECORD}"
cat "$RECORD"
