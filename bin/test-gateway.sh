#!/usr/bin/env bash
# bin/test-gateway.sh - run the gateway crate's unit tests in the same EL8 toolchain the artifact
# is built from (Bundle R).
#
# Why a script instead of `cargo test` on the host: the fleet has no host with a matching toolchain
# (lab-web01 is EL8 without Rust, build01 is EL9 with a different glibc), and a test run on a
# different toolchain than the artifact is a different program. The builder stage of the gateway
# Containerfile is the only environment whose `cargo test` result describes the shipped binary.
#
# Usage: bin/test-gateway.sh [--target TARGET]   (default: the crate in ./gateway)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="${CRATE_DIR:-$REPO_ROOT/gateway}"
PODMAN="${PODMAN:-podman}"
IMAGE="localhost/fleet-filter-gateway-builder:dev"

command -v "$PODMAN" >/dev/null 2>&1 || { echo "podman not found (set PODMAN or install it)" >&2; exit 1; }

echo "building builder stage of $CRATE_DIR/Containerfile"
# `--target builder` stops before the runtime stage, which is what keeps this fast: the builder
# image already caches the compiled dependencies, so a test run only rebuilds the test harness.
"$PODMAN" build --pull=missing --target builder -t "$IMAGE" "$CRATE_DIR" >/dev/null

echo "running cargo test in $IMAGE"
exec "$PODMAN" run --rm "$IMAGE" cargo test --release -- --nocapture
