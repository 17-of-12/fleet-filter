#!/usr/bin/env bash
# webtree-scan-host.sh - run the Stage 4 scanner on this host and publish the report the console reads.
#
# Purpose
# -------
# The fleet console never runs an audit; it reads the report the host produced (`web/sync.py` ->
# `webtree_audits` / `webtree_files`). This script is the host-side half of Bundle Z: the one command
# a systemd timer runs to keep `/var/lib/fleet-filter/webtree-report.json` current.
#
# Design notes
# ------------
# * The scanner is the project image, not a host package (packaging direction 2026-01-16: no vendor
#   yara, no source trees on web hosts). The image is resolved rather than hardcoded because the two
#   hosts name it differently: build01 builds it as `localhost/fleet-filter-scanner:<ver>-<sha>` in the
#   agent's rootless store, while lab-web01 pulls `build01.lab:5000/fleet-filter/scanner:...`
#   into root's store. Resolution order is therefore: explicit $IMAGE, then any local tag whose repo
#   ends in `fleet-filter/scanner` or `fleet-filter-scanner`, newest first.
# * The runtime is resolved the same way (`podman` as the login user, then `sudo -n podman`, then
#   `docker`), and the runtime that actually *has* the image wins. Picking a runtime first and then
#   failing to find the image is the failure this host has hit repeatedly.
# * The report is written to a temporary file and moved into place, so a reader (the sync) never sees
#   a half-written report, and a failed audit leaves the previous report intact.
# * The audit's exit code is meaningful: 0 clean, 10 review, 11 quarantine. Only other codes are
#   failures. Treating "11" as an error would make the scanner unable to report a webshell.
#
# Usage
# -----
#   bin/webtree-scan-host.sh                       # audit /var/www/html, publish to /var/lib/fleet-filter
#   DOCROOT=/srv/www bin/webtree-scan-host.sh      # audit a different tree
#   IMAGE=build01.lab:5000/fleet-filter/scanner:0.1.0-faa9808 bin/webtree-scan-host.sh
#   OUT_DIR=/tmp/demo bin/webtree-scan-host.sh     # write the report somewhere else (test runs)

set -euo pipefail

DOCROOT="${DOCROOT:-/var/www/html}"
OUT_DIR="${OUT_DIR:-/var/lib/fleet-filter}"
IMAGE="${IMAGE:-}"
RUNTIME="${RUNTIME:-}"
# Z5 suppression set. A host file wins over the one baked into the image, so an app-specific
# allowlist can be deployed without rebuilding the scanner; the image default (Composer
# `vendor/`, `node_modules/`, ...) applies whenever the host has not declared its own.
ALLOWLIST_HOST="${ALLOWLIST_HOST:-/etc/fleet-filter/webtree-allowlist}"
ALLOWLIST_IMAGE="/opt/fleet-filter/allowlist/default.allowlist"

die() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

# RUNTIMES lists the container runtimes to consider, in order. A host can hold two podman image
# stores (root's and the login user's rootless store) and only one of them usually holds our image, so
# picking a runtime before looking for the image is the mistake this host has made twice: the audit
# works when the owner runs it as agent and fails as root, or the reverse.
RUNTIMES="${RUNTIMES:-podman,sudo -n podman,docker,sudo -n docker}"

# discover_tag prints the newest scanner image reference visible to $1, preferring a registry-qualified
# name over a `localhost/` tag because the former records where the image came from. `sed -n 1p` is used
# instead of `head -1`: under `set -o pipefail` a `head` that exits early can kill its producer with
# SIGPIPE (exit 141), which is what broke the scanner build once already.
discover_tag() {
    local rt="$1" rows registry local_tag
    # `{{.CreatedAt}}` is a fixed-width UTC timestamp, so sorting the rows sorts by build time.
    # `{{.Created}}` is the relative form ("5 hours ago") and `{{.Repository}}:{{.Tag}}` alone is
    # worse still: tag names are git shas, which have no chronological order, so the previous
    # name-sorted logic kept running a 5-hour-old image after a newer build was published.
    rows="$($rt images --format '{{.CreatedAt}}\t{{.Repository}}:{{.Tag}}' 2>/dev/null \
            | awk -F'\t' '$2 ~ /fleet-filter[\/_-]scanner:/ && $2 !~ /<none>/' | sort -r)" || true
    [ -n "$rows" ] || return 1
    # Prefer a registry-qualified reference over a `localhost/` tag for the same build: the former
    # records where the image came from. `awk ... exit` instead of `head -1`, which has killed a
    # build here before with SIGPIPE under `set -o pipefail`.
    registry="$(printf '%s\n' "$rows" | awk -F'\t' '$2 ~ /^[A-Za-z0-9.-]+:[0-9]+\// {print $2; exit}')"
    [ -n "$registry" ] && { printf '%s\n' "$registry"; return 0; }
    printf '%s\n' "$(printf '%s\n' "$rows" | awk -F'\t' '$2 !~ /:latest$/ {print $2; exit}')"
}

# find_image prints "<runtime><TAB><image>" for the first runtime that can run and holds the image.
# With no image requested it takes the newest scanner tag any runtime can see.
find_image() {
    local wanted="${1:-}" list rt tag
    IFS=',' read -r -a list <<< "$RUNTIMES"
    for rt in "${list[@]}"; do
        [ -n "$rt" ] || continue
        $rt --version >/dev/null 2>&1 || continue
        if [ -n "$wanted" ]; then
            if $rt image exists "$wanted" >/dev/null 2>&1; then
                printf '%s\t%s\n' "$rt" "$wanted"
                return 0
            fi
        else
            tag="$(discover_tag "$rt")" || true
            if [ -n "$tag" ]; then
                printf '%s\t%s\n' "$rt" "$tag"
                return 0
            fi
        fi
    done
    return 1
}

main() {
    [ -d "$DOCROOT" ] || die "docroot $DOCROOT does not exist"
    local runtime image tmp found rc=0
    if [ -n "$RUNTIME" ] && [ -n "$IMAGE" ]; then
        runtime="$RUNTIME"
        image="$IMAGE"
    else
        found="$(find_image "$IMAGE")" || die "no runtime holding a scanner image ($RUNTIMES)"
        runtime="${found%%$'\t'*}"
        image="${found#*$'\t'}"
    fi
    mkdir -p "$OUT_DIR"
    tmp="$(mktemp "$OUT_DIR/.webtree-report.XXXXXX")"
    # The allowlist has to be readable *inside* the container, so a host-only file is bind-mounted
    # at its own path rather than passed as a path the container cannot see. An image built before
    # Z5 simply has no such file, and webtree-audit.py treats a missing allowlist as empty.
    set --
    if [ -f "$ALLOWLIST_HOST" ]; then
        set -- "$@" -v "$ALLOWLIST_HOST:$ALLOWLIST_HOST:ro"
        allowlist="$ALLOWLIST_HOST"
    else
        allowlist="$ALLOWLIST_IMAGE"
    fi
    # shellcheck disable=SC2086  # $runtime is intentionally a word list ("sudo -n podman")
    $runtime run --rm --network=none \
        -v "$DOCROOT:$DOCROOT:ro" \
        -v "$OUT_DIR:$OUT_DIR" \
        "$@" \
        "$image" "$DOCROOT" \
        --allowlist "$allowlist" \
        --state "$OUT_DIR/webtree-audit.state.json" \
        --json "$tmp" --quiet || rc=$?
    case "$rc" in
        0 | 10 | 11) ;;
        *) rm -f "$tmp"; die "audit failed with exit $rc (report left untouched)" ;;
    esac
    chmod 0644 "$tmp"
    mv -f "$tmp" "$OUT_DIR/webtree-report.json"
    printf 'published %s (audit exit %s, runtime %s, image %s)\n' \
        "$OUT_DIR/webtree-report.json" "$rc" "$runtime" "$image"
}

main "$@"
