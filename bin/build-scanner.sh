#!/usr/bin/env bash
# bin/build-scanner.sh - build, verify, and publish the Stage 4 scanner image (Bundle Z packaging).
#
# What this proves, in order, and why each step is a gate rather than a courtesy:
#   1. the pins in scanner/config.yaml are readable and complete (an image built from guessed
#      versions is not a reproducible artifact);
#   2. the yara source tarball hashes to the recorded sha256 before it is ever handed to the
#      builder, so a tampered or truncated download fails here instead of producing an image whose
#      scanner nobody can reproduce;
#   3. the image builds from scanner/Containerfile with the project's own code and ruleset inside;
#   4. the built image is *run*, not just built: yara reports the pinned version, gitleaks reports
#      the pinned version, the shipped ruleset compiles, and an audit of the image's own fixture
#      tree produces the verdicts the fixtures were designed to produce. A scanner that builds but
#      silently detects nothing is the failure mode this project keeps hitting, so the smoke test is
#      the real acceptance criterion for "the scanner works".
#   5. only then is it tagged and pushed to the local registry, and only then is the artifact record
#      written. A failed step leaves no success record behind.
#
# Usage: bin/build-scanner.sh [--no-push] [--no-cache] [--timeout SECONDS] [--dry-run]
#   --no-push     build and verify locally, skip the registry push
#   --no-cache    pass --no-cache to the image build
#   --timeout     seconds allowed for the podman build (default 3600)
#   --dry-run     print the resolved plan (tags, pins, staged context) without building
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCANNER_DIR="${REPO_ROOT}/scanner"
CONFIG="${SCANNER_DIR}/config.yaml"
BUILD_DIR="${SCANNER_DIR}/build"
CACHE_DIR="${REPO_ROOT}/.cache/scanner"
DIST_DIR="${REPO_ROOT}/dist"

NO_PUSH=0
NO_CACHE=0
BUILD_TIMEOUT=3600
DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --no-push)  NO_PUSH=1 ;;
        --no-cache) NO_CACHE=1 ;;
        --timeout)  shift; BUILD_TIMEOUT="${1:?--timeout needs a value}" ;;
        --dry-run)  DRY_RUN=1 ;;
        -h|--help)  sed -n '2,24p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------- pins (scanner/config.yaml is the source)
config_get() {
    # Dotted-path lookup against the YAML file, so the script cannot drift from the recorded pins.
    python3 - "$CONFIG" "$1" <<'PY'
import sys
try:
    import yaml
except ImportError:
    sys.exit("scanner/config.yaml requires PyYAML (python3 -c 'import yaml')")
with open(sys.argv[1]) as handle:
    node = yaml.safe_load(handle) or {}
for part in sys.argv[2].split("."):
    if not isinstance(node, dict) or part not in node:
        sys.exit("config: missing key %r" % sys.argv[2])
    node = node[part]
print(node)
PY
}

VERSION="$(config_get image.version)"
REGISTRY="$(config_get image.registry)"
REPOSITORY="$(config_get image.repository)"
LOCAL_REPO="$(config_get image.local_repository)"
BASE_IMAGE="$(config_get image.base_image)"
BASE_DIGEST="$(config_get image.base_image_digest)"
YARA_VERSION="$(config_get tools.yara.version)"
YARA_URL="$(config_get tools.yara.url)"
YARA_SHA256="$(config_get tools.yara.sha256)"
GITLEAKS_IMAGE="$(config_get tools.gitleaks.image)"
GIT_SHA7="$(git -C "$REPO_ROOT" rev-parse --short=7 HEAD)"
TAG="${REGISTRY}/${REPOSITORY}:${VERSION}-${GIT_SHA7}"
LOCAL_TAG="${LOCAL_REPO}:${VERSION}-${GIT_SHA7}"

echo "repo:        $REPO_ROOT"
echo "git:         $GIT_SHA7"
echo "image tag:   $TAG"
echo "local tag:   $LOCAL_TAG"
echo "base image:  ${BASE_IMAGE}@${BASE_DIGEST}"
echo "yara:        ${YARA_VERSION} sha256:${YARA_SHA256:0:12}..."
echo "gitleaks:    ${GITLEAKS_IMAGE}"

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: nothing built"
    exit 0
fi

# ---------------------------------------------------------------- podman
if [[ -z "${PODMAN:-}" ]]; then
    if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
        PODMAN="podman"
    elif command -v sudo >/dev/null 2>&1 && sudo -n podman info >/dev/null 2>&1; then
        PODMAN="sudo podman"
    else
        echo "error: no usable podman (neither 'podman info' nor 'sudo -n podman info' succeeded)" >&2
        exit 1
    fi
fi
echo "podman:      $PODMAN"

# ---------------------------------------------------------------- stage the build context
# The context is assembled rather than pointed at the repo: the image needs the Containerfile, the
# config record, the ruleset, the analyzer, the fixtures, and the vendored yara tarball, and nothing
# else. Assembling it makes "what is inside this image" a list instead of an inference.
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$CACHE_DIR" "$DIST_DIR"
cp "${SCANNER_DIR}/Containerfile" "${BUILD_DIR}/Containerfile"
cp "$CONFIG" "${BUILD_DIR}/config.yaml"
cp -r "${SCANNER_DIR}/rules" "${BUILD_DIR}/rules"
cp -r "${SCANNER_DIR}/allowlist" "${BUILD_DIR}/allowlist"
cp "${REPO_ROOT}/bin/webtree-audit.py" "${BUILD_DIR}/webtree-audit.py"
cp -r "${REPO_ROOT}/tests/fixtures/webtree" "${BUILD_DIR}/fixtures"

TARBALL="${CACHE_DIR}/yara-${YARA_VERSION}.tar.gz"
if [[ -f "$TARBALL" ]] && ! (cd "$CACHE_DIR" && echo "${YARA_SHA256}  yara-${YARA_VERSION}.tar.gz" | sha256sum -c --status - 2>/dev/null); then
    echo "warning: cached yara tarball does not match the recorded sha256; refetching" >&2
    rm -f "$TARBALL"
fi
if [[ ! -f "$TARBALL" ]]; then
    echo "-- fetching yara ${YARA_VERSION} source --"
    curl -fL --retry 3 --max-time 600 -o "${TARBALL}.tmp" "$YARA_URL"
    (cd "$CACHE_DIR" && echo "${YARA_SHA256}  yara-${YARA_VERSION}.tar.gz.tmp" | sha256sum -c --status)
    mv "${TARBALL}.tmp" "$TARBALL"
fi
cp "$TARBALL" "${BUILD_DIR}/yara.tar.gz"
echo "context:     $BUILD_DIR ($(du -sh "$BUILD_DIR" | awk '{print $1}'))"

# ---------------------------------------------------------------- build
BUILD_ARGS=(--build-arg "BASE_IMAGE=${BASE_IMAGE}@${BASE_DIGEST}"
            --build-arg "YARA_VERSION=${YARA_VERSION}"
            --build-arg "YARA_TARBALL_SHA256=${YARA_SHA256}"
            --build-arg "GITLEAKS_IMAGE=${GITLEAKS_IMAGE}")
[[ "$NO_CACHE" -eq 1 ]] && BUILD_ARGS+=(--no-cache)
echo "-- building (timeout ${BUILD_TIMEOUT}s) --"
timeout "$BUILD_TIMEOUT" $PODMAN build "${BUILD_ARGS[@]}" -t "$TAG" -t "$LOCAL_TAG" "$BUILD_DIR"
# Keep a `latest` on the local repo too, so a host can reference the newest build without the registry.
$PODMAN tag "$TAG" "${LOCAL_REPO}:latest" 2>/dev/null || true

# ---------------------------------------------------------------- smoke test the built image
# Every check below is a claim about the artifact, and each one is checked by running it.
echo "-- smoke test --"
YARA_REPORTED="$($PODMAN run --rm --network=none --entrypoint /usr/bin/yara "$TAG" --version 2>&1 | tr -d '[:space:]')"
if [[ "$YARA_REPORTED" != "${YARA_VERSION}" ]]; then
    echo "error: image yara reported '$YARA_REPORTED', expected '$YARA_VERSION'" >&2
    exit 1
fi
echo "  yara in image:        $YARA_REPORTED"

GITLEAKS_REPORTED="$($PODMAN run --rm --network=none --entrypoint /usr/local/bin/gitleaks "$TAG" version 2>&1 | sed -n '1p' | tr -d '[:space:]')"
if ! printf '%s' "$GITLEAKS_REPORTED" | grep -q "$(config_get tools.gitleaks.version | tr -d 'v')"; then
    echo "error: image gitleaks reported '$GITLEAKS_REPORTED'" >&2
    exit 1
fi
echo "  gitleaks in image:    $GITLEAKS_REPORTED"

# `yara -c` is not a thing in yara 4.x (that flag belongs to yarac), so the compile check runs yarac
# and writes the compiled ruleset to a file the script can inspect. `sed -n '1p'` is used instead of
# `head -1` on purpose: head closes the pipe early and podman then dies of SIGPIPE, which under
# `set -o pipefail` aborts the whole build with exit 141.
YARAC_OUT="$($PODMAN run --rm --network=none --entrypoint /usr/bin/yarac "$TAG" \
    /opt/fleet-filter/rules/fleet-filter.yar /tmp/fleet-filter.yr 2>&1 | sed -n '1,10p')"
if [[ -n "$YARAC_OUT" ]]; then
    echo "error: the shipped ruleset does not compile with the yara in this image" >&2
    printf '%s\n' "$YARAC_OUT" >&2
    exit 1
fi
echo "  ruleset compiles:     /opt/fleet-filter/rules/fleet-filter.yar"

# The fixture tree ships inside the image, so this run needs no mounts and no host state. The report
# lands in a host file: piping it straight into `python3 - <<'PY'` would feed the heredoc to python as
# the program and leave sys.stdin empty, which is how the first version of this check failed.
AUDIT_JSON="$BUILD_DIR/smoke-report.json"
# webtree-audit.py exits 0 (nothing flagged), 10 (something to review) or 11 (something quarantined).
# The fixture tree deliberately contains quarantined files, so 11 is the expected result here; only an
# exit code outside that documented set means the audit itself broke.
set +e
$PODMAN run --rm --network=none "$TAG" /opt/fleet-filter/fixtures \
    --json - --quiet --full > "$AUDIT_JSON" 2>/dev/null
AUDIT_RC=$?
set -e
if [[ "$AUDIT_RC" -gt 11 ]]; then
    echo "error: the audit inside the image exited $AUDIT_RC (expected 0, 10, or 11)" >&2
    exit 1
fi
if [[ ! -s "$AUDIT_JSON" ]]; then
    echo "error: the audit inside the image produced no JSON" >&2
    exit 1
fi
# Expected verdicts per fixture. `quarantine` here is mostly signature-driven (tier 2), which is the
# point: a fixture exists per rule class so a broken ruleset cannot pass as a clean webtree.
SMOKE_OUT="$(python3 - "$AUDIT_JSON" <<'PY'
import json, sys
EXPECTED = {
    "index.html": "clean", "app.js": "clean", "web.config": "clean",
    "small.php": "quarantine", "obf.php": "quarantine",
    # logo.png is a shape-only finding (magic mismatch plus eval/base64_decode, score 6): the shape
    # heuristics flag it but no signature claims it, so the honest verdict is review, matching the
    # assertion in tests/unit/test_webtree_audit.py. Everything else here is signature-driven.
    "logo.png": "review",
    "eicar.txt": "quarantine", "c99shell.php": "quarantine", "shell.jsp": "quarantine",
}
report = json.load(open(sys.argv[1]))
bad = []
found = {}
for record in report.get("files", []):
    name = record.get("path", "").rsplit("/", 1)[-1]
    found[name] = record.get("verdict")
for name, want in EXPECTED.items():
    got = found.get(name)
    if got != want:
        bad.append("%s: expected %s, got %s" % (name, want, got))
if len(found) != len(EXPECTED):
    bad.append("fixture count: expected %d, audited %d" % (len(EXPECTED), len(found)))
if bad:
    print("\n".join(bad))
    sys.exit(1)
print("  fixture audit:        %d files, summary %s"
      % (report["files_audited"], report["summary"]))
PY
)" || { echo "error: fixture audit did not match the expected verdicts:" >&2; \
        printf '%s\n' "$SMOKE_OUT" >&2; exit 1; }
echo "$SMOKE_OUT"

# ---------------------------------------------------------------- publish
IMAGE_DIGEST=""
if [[ "$NO_PUSH" -eq 0 ]]; then
    echo "-- pushing to $REGISTRY --"
    AUTH_ARGS=()
    if [[ "$PODMAN" == sudo* && -f /home/agent/.docker/config.json ]]; then
        # root's podman does not read the agent's auth file, so name it explicitly.
        AUTH_ARGS=(--authfile /home/agent/.docker/config.json)
    fi
    $PODMAN push "${AUTH_ARGS[@]}" "$TAG"
    IMAGE_DIGEST="$($PODMAN inspect --format '{{index .RepoDigests 0}}' "$TAG" 2>/dev/null | \
                   sed 's/^.*@//' || true)"
fi

# ---------------------------------------------------------------- artifact record
ARTIFACT="${DIST_DIR}/fleet-filter-scanner-${VERSION}-${GIT_SHA7}.json"
python3 - "$ARTIFACT" "$TAG" "$LOCAL_TAG" "$IMAGE_DIGEST" "$GIT_SHA7" "$VERSION" \
    "${BASE_IMAGE}@${BASE_DIGEST}" "$YARA_VERSION" "$YARA_SHA256" "$GITLEAKS_IMAGE" <<'PY'
import datetime, json, sys
(out, tag, local_tag, digest, git_sha, version, base, yara_version, yara_sha, gitleaks) = sys.argv[1:11]
json.dump({
    "component": "stage4-scanner",
    "version": version,
    "git_sha": git_sha,
    "built_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "image_tag": tag,
    "local_image_tag": local_tag,
    "image_digest": digest,
    "base_image": base,
    "tools": {"yara": {"version": yara_version, "tarball_sha256": yara_sha},
              "gitleaks": {"image": gitleaks}},
    "containerfile": "scanner/Containerfile",
    "ruleset": "scanner/rules/fleet-filter.yar",
    "analyzer": "bin/webtree-audit.py",
    "verified": ["yara version matches pin", "gitleaks version matches pin",
                 "ruleset compiles", "fixture tree audit matches expected verdicts"],
}, open(out, "w"), indent=2, sort_keys=True)
print("artifact:    %s" % out)
PY

if [[ "$NO_PUSH" -eq 0 && -z "$IMAGE_DIGEST" ]]; then
    echo "warning: push succeeded but no registry digest was recorded" >&2
fi
echo "done: $TAG"
