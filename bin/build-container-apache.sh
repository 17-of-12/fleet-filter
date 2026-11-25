#!/usr/bin/env bash
# bin/build-container-apache.sh - build and record the Stage 3 canary image (Bundle V).
#
# Runs from a project checkout (here) or from a deployed staging tree on the target host. It builds
# the image from `container/Containerfile`, tags it with the git sha so a running container can be
# traced to a commit, verifies the baked configuration actually parses (`httpd -t`) and captures the
# module list, then writes the provenance record next to the gateway's binary provenance records.
#
# Usage: bin/build-container-apache.sh [--runtime podman|docker] [--git-sha SHA] [--no-push]
#   --no-push   build and verify locally, skip the registry push (the pre-2026-11-16 behaviour)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME=""
GITSHA_OVERRIDE=""
NO_PUSH=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --runtime) RUNTIME="$2"; shift 2 ;;
        --git-sha) GITSHA_OVERRIDE="$2"; shift 2 ;;
        --no-push) NO_PUSH=1; shift ;;
        *) echo "build-container-apache: unknown argument $1" >&2; exit 64 ;;
    esac
done

if [[ -z "$RUNTIME" ]]; then
    if command -v podman >/dev/null 2>&1; then RUNTIME=podman
    elif command -v docker >/dev/null 2>&1; then RUNTIME=docker
    else echo "no container runtime found (need podman or docker)" >&2; exit 1; fi
fi

CONFIG="$REPO/container/config.yaml"
[[ -f "$CONFIG" ]] || { echo "missing $CONFIG" >&2; exit 1; }

read -r IMAGE_NAME IMAGE_VERSION BASE_IMAGE BASE_DIGEST TARGET_HOST REGISTRY REPOSITORY < <(python3 - "$CONFIG" <<'PY'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
base = cfg["image"]["base_image"]
digest = cfg["image"].get("base_image_digest", "")
# An older config has no registry keys; that is "build locally only", not a missing file.
print(cfg["image"]["name"], cfg["image"]["version"], base, digest, cfg["target"]["hostname"],
      cfg["image"].get("registry", ""), cfg["image"].get("repository", ""))
PY
)

GITSHA="${GITSHA_OVERRIDE:-$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
TAG="$IMAGE_NAME:$IMAGE_VERSION-$GITSHA"
# The registry name is the deployable identity (owner directive: build on build01, deploy out);
# the `localhost/...` name stays so a host that already references it keeps working, and the
# compose file continues to name the local tag rather than the registry URL.
REGISTRY_TAG=""
if [[ -n "$REGISTRY" && -n "$REPOSITORY" ]]; then
    REGISTRY_TAG="$REGISTRY/$REPOSITORY:$IMAGE_VERSION-$GITSHA"
fi
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fleet-filter-apache-build.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

# The build context is `container/`, never the repo root: the Containerfile copies only
# `canary/`, so a repo-root context would rebuild on every unrelated commit.
cp "$REPO/container/Containerfile" "$BUILD_DIR/Containerfile"
cp -R "$REPO/container/canary" "$BUILD_DIR/canary"

echo "building $TAG with $RUNTIME from $BASE_IMAGE (digest ${BASE_DIGEST:-unresolved})"
[[ -n "$REGISTRY_TAG" ]] && echo "registry tag: $REGISTRY_TAG"
EXTRA_TAGS=()
[[ -n "$REGISTRY_TAG" ]] && EXTRA_TAGS=(--tag "$REGISTRY_TAG")
"$RUNTIME" build \
    --file "$BUILD_DIR/Containerfile" \
    --build-arg "BASE_IMAGE=$([ "$BASE_DIGEST" = "pending-at-first-build" ] && echo "$BASE_IMAGE" || echo "$BASE_IMAGE@$BASE_DIGEST")" \
    --build-arg "FLEET_FILTER_VERSION=$IMAGE_VERSION" \
    --build-arg "VCS_REF=$GITSHA" \
    --label "io.fleet-filter.vcs-ref=$GITSHA" \
    --tag "$TAG" \
    "${EXTRA_TAGS[@]+"${EXTRA_TAGS[@]}"}" \
    --tag "$IMAGE_NAME:$IMAGE_VERSION" \
    "$BUILD_DIR"

# A configuration that only fails at start time is a configuration that wastes a deploy. `httpd -t`
# catches syntax and module-load failures inside the image, before anything is published.
echo "validating the baked configuration inside the image"
"$RUNTIME" run --rm --entrypoint /usr/sbin/httpd "$TAG" -t -D DUMP_MODULES 2>&1 \
    | tr -s ' \n' ' ' > "$BUILD_DIR/modules.txt"
"$RUNTIME" run --rm --entrypoint /usr/sbin/httpd "$TAG" -t 2>&1 | tail -1

# SBOM: the package set baked into the image. Captured from the image itself rather than from the
# host, because the image's rpmdb is what a running container actually contains - the two diverge
# the moment the base image digest moves. Plain `rpm -qa` output is parsed instead of an rpm
# query format string: a `--qf` template has to survive two layers of shell quoting to reach the
# container, and the first attempt at it produced an empty file with a non-zero rpm error buried
# under `2>/dev/null`. NEVRA parsing has no such failure mode.
"$RUNTIME" run --rm --entrypoint /usr/bin/rpm "$TAG" -qa 2>/dev/null | sort > "$BUILD_DIR/sbom.txt"
if [[ ! -s "$BUILD_DIR/sbom.txt" ]]; then
    echo "build-container-apache: the image produced an empty package list; refusing to record an empty SBOM" >&2
    exit 1
fi

IMAGE_ID="$("$RUNTIME" inspect --format '{{.Id}}' "$TAG")"
# Publish before recording: the artifact is the proof of a publishable image, and a push that fails
# should leave the record behind the build rather than claiming an artifact nobody can pull.
REGISTRY_DIGEST=""
if [[ -n "$REGISTRY_TAG" && "$NO_PUSH" -eq 0 ]]; then
    echo "pushing $REGISTRY_TAG"
    AUTH_ARGS=()
    if [[ "$RUNTIME" == sudo* && -f /home/agent/.docker/config.json ]]; then
        # root's podman does not read the agent's auth file, so name it explicitly.
        AUTH_ARGS=(--authfile /home/agent/.docker/config.json)
    fi
    "$RUNTIME" push "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" "$REGISTRY_TAG"
    REGISTRY_DIGEST="$("$RUNTIME" inspect --format '{{index .RepoDigests 0}}' "$REGISTRY_TAG" 2>/dev/null | sed 's/^.*@//' || true)"
    # No registry `:latest` here, unlike the scanner's local tag: the project rule is that the sha
    # tag is the deploy identity, and a pushed `latest` that nothing reads is the kind of second
    # source of truth this project has already been bitten by.
    [[ -n "$REGISTRY_DIGEST" ]] || echo "warning: push succeeded but no registry digest was recorded" >&2
fi
ARTIFACT_DIR="$REPO/data/artifacts"
[[ -d "$REPO/.git" || -d "$ARTIFACT_DIR" ]] || ARTIFACT_DIR="$REPO"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT="$ARTIFACT_DIR/fleet-filter-apache-$IMAGE_VERSION-$GITSHA.json"
python3 - "$ARTIFACT" "$IMAGE_NAME" "$IMAGE_VERSION" "$GITSHA" "$BASE_IMAGE" "$BASE_DIGEST" \
         "$IMAGE_ID" "$RUNTIME" "$(hostname -f 2>/dev/null || hostname)" "$BUILD_DIR/modules.txt" \
         "$BUILD_DIR/sbom.txt" "$REGISTRY_TAG" "$REGISTRY_DIGEST" <<'PY'
import hashlib, json, sys
(out, name, version, gitsha, base, base_digest, image_id, runtime, host, modules, sbom_path,
 registry_tag, registry_digest) = sys.argv[1:14]
sbom_bytes = open(sbom_path, "rb").read()
sbom = []
for line in sbom_bytes.decode("utf-8").splitlines():
    nvra = line.strip()
    if not nvra:
        continue
    # rpm prints `name-version-release.arch`; the name may itself contain dashes, so split the
    # version off the last two fields rather than the first two.
    head, _, release = nvra.rpartition("-")
    name_part, _, version_part = head.rpartition("-")
    arch = release.rpartition(".")[2] if "." in release else ""
    sbom.append({"name": name_part, "version": version_part,
                 "release": release.rpartition(".")[0] if "." in release else release,
                 "arch": arch, "nevra": nvra})
record = {
    "sbom_format": "rpm -qa from the built image, parsed into name/version/release/arch",
    "sbom_package_count": len(sbom),
    "sbom_sha256": hashlib.sha256(sbom_bytes).hexdigest(),
    "sbom": sbom,
    "artifact": name,
    "version": version,
    "git_sha": gitsha,
    "base_image": base,
    "base_image_digest": base_digest,
    "image_id": image_id,
    "image_tag": registry_tag or name,
    "local_image_tag": name,
    "registry_digest": registry_digest,
    "pushed_to_registry": bool(registry_digest),
    "built_with": runtime,
    "build_host": host,
    "modules": open(modules, encoding="utf-8").read().strip(),
    "containerfile": "container/Containerfile",
    "config": "container/config.yaml",
}
with open(out, "w", encoding="utf-8") as handle:
    json.dump(record, handle, indent=2)
    handle.write("\n")
print(f"wrote {out}")
PY

echo "built $TAG ($IMAGE_ID)"
