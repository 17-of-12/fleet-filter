#!/usr/bin/env python3
"""Report, and optionally apply, container-image retention on this build host.

Why this exists
---------------
build01 is at 88% on `/` with 9.1 GB free, and `podman system df` reports 5.286 GB in the rootless
image store as **100% reclaimable**. Nothing has broken yet, which is exactly when retention gets
forgotten: a build host that fills its root filesystem takes the console, the local registry, and
the gateway rebuild timer down together. Every build leaves layers behind - a Rust builder-stage
image is ~1.1 GB, and superseded gateway and scanner tags are 263 MB and 332 MB each - so the
growth is structural, not an accident.

Why not `podman system prune`
-----------------------------
`podman system prune` also stops and removes containers, and on build01 the root podman store holds
`frameprobe` and `h2probe` images while Docker holds Semaphore UI, Postgres, and Nagios. The owner
rule (2026-11-16) is that this project does not touch other projects' resources, so this script
names the repositories it owns and removes nothing else. Podman 5.8.2 also has no `--dry-run` for
`image prune` and no `--until`, so the set is enumerated and filtered here - which makes the plan
reviewable before anything is removed, instead of only afterwards.

Retention model
---------------
  * per owned repository, keep the newest `--keep` tags (default 3) plus `latest`;
  * untag anything older than that, which is what turns it into a dangling image;
  * then remove dangling images older than `--min-age-hours` (default 24) that no container
    references. The age floor protects an image a build created minutes ago but has not finished
    tagging - removing that mid-build is how a build host loses an artifact it is about to publish.

Dry run is the default; `--apply` is required to remove anything, matching bin/webtree-quarantine.py.

Usage
-----
    bin/prune-build-host.py                       # report the plan
    bin/prune-build-host.py --apply               # execute it
    bin/prune-build-host.py --include-root        # also consider the root podman store
    bin/prune-build-host.py --keep 5 --json       # different retention, machine-readable output

Stdlib-only and Python 3.6+ so it runs on any fleet host, matching the other bin/ tools.
"""

import argparse
import calendar
import datetime
import json
import shutil
import subprocess
import sys

# Repositories this project publishes. Anything else in a shared store belongs to another project
# and is never untagged or removed here, even when it is dangling.
OWNED_REPOS = (
    "localhost/fleet-filter-gateway",
    "localhost/fleet-filter-scanner",
    "build01.lab:5000/fleet-filter/gateway",
    "build01.lab:5000/fleet-filter/scanner",
)

DEFAULT_KEEP = 3
DEFAULT_MIN_AGE_HOURS = 24


def run(argv, timeout=120):
    """Run a command and return stdout, or None when it fails or is unavailable.

    Every probe here is read-only except the removals in `apply`, so a failure means "this runtime
    or image is not queryable", not "the host is broken" - and the caller decides whether that is
    fatal (no runtime at all) or ignorable (one image refused to be inspected).
    """
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, universal_newlines=True)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def discover_runtimes(include_root=False, podman=None):
    """Return the podman invocations to inspect.

    Default is the runtime the current user can use without a password prompt, which on build01 is
    rootless `podman` for agent. `--include-root` adds `sudo -n podman`: that store holds other
    projects' images, so it is opt-in rather than automatic, and skipped silently when sudo is not
    available non-interactively (for example under a `NoNewPrivileges=yes` service).
    """
    runtimes = []
    if podman:
        runtimes.append(podman.split() if isinstance(podman, str) else list(podman))
    else:
        found = shutil.which("podman")
        if found:
            runtimes.append([found])
        elif subprocess.run(["sudo", "-n", "podman", "--version"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            runtimes.append(["sudo", "-n", "podman"])
    if include_root:
        root = ["sudo", "-n", "podman"]
        if subprocess.run(root + ["--version"], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0 and root not in runtimes:
            runtimes.append(root)
    return runtimes


def parse_image_rows(text):
    """Parse `images --format '{{.Repository}}:{{.Tag}}|{{.CreatedAt}}|{{.ID}}'` output.

    Returns `[(reference, created_iso, image_id), ...]`. Dangling rows arrive as `<none>:<none>`;
    they are kept because the dangling set is the bulk of what retention removes.
    """
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.count("|") < 2:
            continue
        reference, created, image = line.split("|", 2)
        if image.strip():
            rows.append((reference.strip(), created.strip(), image.strip()))
    return rows


def repo_of(reference):
    """Repository part of an image reference, without its tag.

    Splitting on the first colon is wrong for a registry that carries a port
    (`build01.lab:5000/fleet-filter/scanner:0.1.0-ae6ba2d`), which is exactly how this
    project's own images are named, so the tag is removed from the right-hand end instead.
    """
    return reference.rsplit(":", 1)[0] if ":" in reference else reference


def list_images(runtime):
    """Every image the runtime reports, tagged and dangling, as parsed rows."""
    return parse_image_rows(run(list(runtime) + [
        "images", "-a", "--format", "{{.Repository}}:{{.Tag}}|{{.CreatedAt}}|{{.ID}}"]))


def image_size(runtime, image_id):
    """Size in bytes for one image, or 0 when it cannot be read."""
    out = run(list(runtime) + ["image", "inspect", "--format", "{{.Size}}", image_id])
    try:
        return int((out or "").strip().splitlines()[0])
    except (IndexError, ValueError):
        return 0


def parse_created(value):
    """Convert a podman timestamp into epoch seconds, or 0 when it cannot be read.

    podman prints either `2026-11-16 19:12:26.381638998 +0000 UTC` (inspect) or
    `2026-11-16 19:12:26 +0000 UTC` (images listing). Two details cost real debugging time:
    Python 3.9's `%f` accepts at most six fractional digits, so nanoseconds have to be truncated,
    and the `T` form has no space before the time. The offset and zone name are dropped rather
    than parsed, because both spellings agree the clock is UTC.

    An unparseable age returns 0, which callers treat as "not old enough to remove" - never as
    "oldest". Removing an image because its metadata was unreadable is worse than leaving a layer.
    """
    value = (value or "").strip()
    if not value:
        return 0
    parts = value.split()
    candidates = [parts[0]] if "T" in parts[0] else ([" ".join(parts[:2])] if len(parts) >= 2 else [])
    for candidate in candidates:
        if "." in candidate.split(" ")[-1]:
            clock, _, fraction = candidate.rpartition(".")
            candidate = "%s.%s" % (clock, fraction[:6])
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                return calendar.timegm(datetime.datetime.strptime(candidate, fmt).utctimetuple())
            except ValueError:
                continue
    return 0


def image_created(runtime, image_id):
    """Creation time of one image as epoch seconds (0 when unreadable)."""
    return parse_created(run(list(runtime) + ["image", "inspect", "--format",
                                             "{{.Created}}", image_id]))


def referenced_images(runtime):
    """Image ids referenced by containers (running or stopped) - removing those breaks a container."""
    out = run(list(runtime) + ["ps", "-a", "--format", "{{.Image}}"])
    return set(line.strip() for line in (out or "").splitlines() if line.strip())


def plan_for_runtime(runtime, keep, min_age_hours, now):
    """Build the removal plan for one runtime: `{"untag": [...], "remove": [...], ...}`.

    Two phases, in the order podman itself requires: superseded tags are untagged first, and only
    then is the dangling set evaluated, so an image that loses its last tag in this run is still
    subject to the age floor rather than being removed the instant it becomes untagged.
    """
    rows = list_images(runtime)
    by_image = {}
    created_by_image = {}
    for reference, created, image in rows:
        by_image.setdefault(image, []).append(reference)
        if image not in created_by_image and created:
            created_by_image[image] = created

    untag = []
    repos = sorted(set(repo_of(ref) for ref, _c, _i in rows if ref != "<none>:<none>"))
    for repo in repos:
        if repo not in OWNED_REPOS:
            continue
        tagged = sorted([row for row in rows if repo_of(row[0]) == repo],
                        key=lambda row: row[1], reverse=True)
        versioned = [row[0] for row in tagged if not row[0].endswith(":latest")]
        retained = min(keep, len(versioned))
        for reference in versioned[keep:]:
            untag.append({"reference": reference,
                          "reason": "superseded (keeping the %d newest plus latest)" % retained})

    protected = referenced_images(runtime)
    remove = []
    for image, references in sorted(by_image.items()):
        remaining = [ref for ref in references
                     if not any(entry["reference"] == ref for entry in untag)]
        dangling_now = references == ["<none>:<none>"]
        becomes_dangling = bool(references) and not remaining
        if not (dangling_now or becomes_dangling):
            continue
        if image in protected:
            continue
        created = parse_created(created_by_image.get(image, "")) or image_created(runtime, image)
        if not created:
            continue
        age_hours = (now - created) // 3600
        if age_hours < min_age_hours:
            continue
        remove.append({"image": image, "age_hours": age_hours,
                       "size": image_size(runtime, image),
                       "reason": "dangling" if dangling_now else "dangling after untag"})

    # `image inspect .Size` is the image's *virtual* size and counts shared layers once per image,
    # so summing it over 299 dangling images reports ~89 GB in a 5.3 GB store. It is still the right
    # number for ranking which images are worth removing; the bytes actually freed come from
    # `podman system df` before and after, which is what `report_apply` reports.
    virtual = sum(entry["size"] for entry in remove)
    return {"runtime": " ".join(runtime), "images": len(rows), "untag": untag,
            "remove": remove, "virtual_bytes": virtual}


def humanize(size):
    """Render a byte count the way `podman images` does, so the report matches the tool it replaces."""
    value = float(size)
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return ("%d%s" % (value, unit)) if unit == "B" else ("%.4g%s" % (value, unit))
        value /= 1024.0
    return "%dB" % size


def build_plan(runtimes, keep, min_age_hours):
    """Collect plans for every runtime in scope."""
    now = calendar.timegm(datetime.datetime.utcnow().utctimetuple())
    return [plan_for_runtime(runtime, keep, min_age_hours, now) for runtime in runtimes]


def render(plan):
    """Render the plan as the plain-text report the tool prints by default."""
    lines = []
    total = 0
    for entry in plan:
        total += entry["virtual_bytes"]
        lines.append("runtime: %s  images: %d  virtual size of removable images: %s"
                     % (entry["runtime"], entry["images"], humanize(entry["virtual_bytes"])))
        lines.append("  untag (%d):" % len(entry["untag"]))
        for item in entry["untag"][:50]:
            lines.append("    %s  %s" % (item["reference"], item["reason"]))
        if not entry["untag"]:
            lines.append("    (none)")
        lines.append("  remove (%d):" % len(entry["remove"]))
        for item in entry["remove"][:50]:
            lines.append("    %s  %s  %dh old  %s"
                         % (item["image"], humanize(item["size"]), item["age_hours"],
                            item["reason"]))
        if not entry["remove"]:
            lines.append("    (none)")
        if len(entry["remove"]) > 50 or len(entry["untag"]) > 50:
            lines.append("    (truncated; use --json for the full plan)")
        lines.append("")
    lines.append("total virtual size (shared layers counted per image; see --apply for the real"
                 " number from `podman system df`): %s" % humanize(total))
    return "\n".join(lines)


def disk_usage(runtime):
    """Bytes in use according to `podman system df`, or 0 when the runtime cannot say.

    This is the only honest "bytes freed" number: per-image sizes count shared layers once per
    image, so removing ten images that share a base frees far less than their sizes summed.
    """
    out = run(list(runtime) + ["system", "df", "--format", "json"])
    try:
        payload = json.loads(out or "{}")
    except ValueError:
        return 0
    total = 0
    # podman 5.x returns a list of `{"Type": "Images", "RawSize": ...}` records; older and Docker
    # shapes return a dict keyed by resource with a `size` field. Both are read so the number is
    # comparable across the runtimes this project builds on.
    if isinstance(payload, list):
        for entry in payload:
            try:
                total += int(entry.get("RawSize", entry.get("rawSize", 0)))
            except (AttributeError, TypeError, ValueError):
                continue
    elif isinstance(payload, dict):
        for value in payload.values():
            entries = value if isinstance(value, list) else [value]
            for entry in entries:
                if isinstance(entry, dict):
                    try:
                        total += int(entry.get("size", entry.get("Size", 0)))
                    except (TypeError, ValueError):
                        continue
    return total


def apply_plan(runtime_plan):
    """Execute one runtime's plan: untag first, then remove. Returns (untagged, removed, errors)."""
    runtime = runtime_plan["runtime"].split()
    untagged = removed = 0
    errors = []
    for item in runtime_plan["untag"]:
        if run(runtime + ["rmi", "-f", item["reference"]]) is None:
            errors.append("rmi tag %s" % item["reference"])
        else:
            untagged += 1
    for item in runtime_plan["remove"]:
        if run(runtime + ["rmi", "-f", item["image"]]) is None:
            errors.append("rmi image %s" % item["image"])
        else:
            removed += 1
    return untagged, removed, errors


def main(argv=None):
    """Entry point: parse flags, build the plan, print it, and remove things when told to."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], add_help=False)
    parser.add_argument("--apply", action="store_true",
                        help="remove the images; without it nothing is changed")
    parser.add_argument("--keep", type=int, default=DEFAULT_KEEP,
                        help="tags to keep per owned repository (default %d)" % DEFAULT_KEEP)
    parser.add_argument("--min-age-hours", type=int, default=DEFAULT_MIN_AGE_HOURS,
                        help="minimum age before a dangling image is removed (default %d)"
                             % DEFAULT_MIN_AGE_HOURS)
    parser.add_argument("--include-root", action="store_true",
                        help="also consider the root podman store (other projects' images live there)")
    parser.add_argument("--podman", default=None, help="podman command to use (default: auto-detect)")
    parser.add_argument("--json", action="store_true", help="emit the plan as JSON")
    parser.add_argument("-h", "--help", action="help")
    args = parser.parse_args(argv)

    runtimes = discover_runtimes(include_root=args.include_root, podman=args.podman)
    if not runtimes:
        sys.stderr.write("no usable podman runtime found\n")
        return 1
    plan = build_plan(runtimes, args.keep, args.min_age_hours)

    if args.json:
        sys.stdout.write(json.dumps({"apply": args.apply, "keep": args.keep,
                                     "min_age_hours": args.min_age_hours,
                                     "runtimes": plan}, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render(plan) + "\n")

    if not args.apply:
        return 0
    failures = 0
    for entry in plan:
        runtime = entry["runtime"].split()
        before = disk_usage(runtime)
        untagged, removed, errors = apply_plan(entry)
        after = disk_usage(runtime)
        for error in errors:
            sys.stderr.write("error: %s: %s\n" % (entry["runtime"], error))
        failures += len(errors)
        result = {"runtime": entry["runtime"], "tags_removed": untagged, "images_removed": removed,
                  "errors": len(errors), "disk_before_bytes": before, "disk_after_bytes": after,
                  "freed_bytes": max(before - after, 0)}
        if args.json:
            sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
        else:
            sys.stdout.write("applied %s: %d tags removed, %d images removed, %s freed, %d error(s)\n"
                             % (entry["runtime"], untagged, removed, humanize(result["freed_bytes"]),
                                len(errors)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
