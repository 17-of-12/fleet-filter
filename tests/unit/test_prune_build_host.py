#!/usr/bin/env python3
"""Tests for bin/prune-build-host.py (build-host image retention).

The tool's job is to remove the right images and nothing else, so the tests are built around the
two ways it can be wrong: an image that should have survived loses its last tag, or an image that
should have been removed survives forever. Everything podman would answer is stubbed here, so the
suites run on a host with no container runtime and cannot accidentally delete real images.

Run directly (`python3.9 tests/unit/test_prune_build_host.py`) the way bin/check.sh runs suites.
"""

import importlib.util
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(REPO_ROOT, "bin", "prune-build-host.py")

sys.path.insert(0, os.path.dirname(SCRIPT))
_spec = importlib.util.spec_from_file_location("prune_build_host", SCRIPT)
pbh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pbh)

PASS = 0
FAIL = 0
NOW = 1794857000          # 2026-11-16T19:23:20Z, the session's reference clock


def check(condition, message, detail=""):
    """Record one assertion result."""
    global PASS, FAIL
    if condition:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL %s %s" % (message, detail))


def test_parse_created():
    """Every timestamp shape podman prints, plus the Python 3.9 nanosecond limit.

    `image inspect` prints nanoseconds (`19:12:26.381638998`) while `images` prints seconds
    (`19:12:26`), and Python 3.9's `%f` accepts at most six fractional digits - a value with nine
    digits fails to parse, which the first version of this tool hit in production.
    """
    check(pbh.parse_created("2026-11-16 19:12:26.381638998 +0000 UTC") == 1794856346,
          "inspect form with nanoseconds is truncated to microseconds and parsed",
          str(pbh.parse_created("2026-11-16 19:12:26.381638998 +0000 UTC")))
    check(pbh.parse_created("2026-11-16 19:12:26 +0000 UTC") == 1794856346,
          "listing form without a fractional part is parsed")
    check(pbh.parse_created("2026-11-16T19:12:26.381638998+00:00") == 1794856346,
          "ISO T form is parsed")
    check(pbh.parse_created("") == 0 and pbh.parse_created(None) == 0,
          "an empty timestamp is 0, not a crash")
    check(pbh.parse_created("yesterday") == 0,
          "an unparseable timestamp is 0, which callers treat as too young to remove")


def test_repo_of():
    """Repository extraction has to survive a registry that carries a port."""
    check(pbh.repo_of("build01.lab:5000/fleet-filter/scanner:0.1.0-ae6ba2d")
          == "build01.lab:5000/fleet-filter/scanner",
          "a registry with a port keeps its port in the repository name")
    check(pbh.repo_of("localhost/fleet-filter-gateway:0.1.0-264fa41")
          == "localhost/fleet-filter-gateway",
          "a plain repository and tag split on the last colon")
    check(pbh.repo_of("<none>:<none>") == "<none>",
          "a dangling reference reports the <none> repository")


def test_parse_image_rows():
    """The listing parser ignores malformed lines and keeps dangling rows."""
    rows = pbh.parse_image_rows(
        "localhost/fleet-filter-gateway:latest|2026-11-16 19:12:26 +0000 UTC|96210b8d8e6d\n"
        "<none>:<none>|2026-11-15 18:45:28 +0000 UTC|7a26fc98a1a0\n"
        "\n"
        "not-a-row-without-pipes\n"
        "repo:tag||\n")
    check([(r[0], r[2]) for r in rows] == [("localhost/fleet-filter-gateway:latest", "96210b8d8e6d"),
                                           ("<none>:<none>", "7a26fc98a1a0")],
          "well-formed rows are kept and malformed ones dropped", str(rows))
    check(pbh.parse_image_rows(None) == [] and pbh.parse_image_rows("") == [],
          "empty output parses to no rows")


def fake_runtime(monkeypatch, images, sizes=None, created=None, containers=()):
    """Replace the podman probes with canned answers for one runtime."""
    sizes = sizes or {}
    created = created or {}
    monkeypatch["images"] = images
    monkeypatch["sizes"] = sizes
    monkeypatch["created"] = created
    monkeypatch["containers"] = list(containers)
    original = {}
    for name in ("list_images", "image_size", "image_created", "referenced_images"):
        original[name] = getattr(pbh, name)

    def list_images(runtime):
        """Canned `podman images -a` rows for the fake runtime."""
        return list(monkeypatch["images"])

    def image_size(runtime, image):
        """Canned per-image byte size for the fake runtime."""
        return int(monkeypatch["sizes"].get(image, 0))

    def image_created(runtime, image):
        """Canned creation epoch for the fake runtime's images."""
        return int(monkeypatch["created"].get(image, 0))

    def referenced_images(runtime):
        """Canned set of image ids still referenced by containers."""
        return set(monkeypatch["containers"])

    pbh.list_images = list_images
    pbh.image_size = image_size
    pbh.image_created = image_created
    pbh.referenced_images = referenced_images
    return original


def restore(monkeypatch, original):
    """Put the real podman probes back after a fake-runtime test."""
    for name, value in original.items():
        setattr(pbh, name, value)


def test_retention_keeps_newest_tags_and_latest():
    """Only the newest N tags plus `latest` survive; older ones are untagged, never deleted outright."""
    monkeypatch = {}
    images = [
        ("localhost/fleet-filter-gateway:0.1.0-newest", "2026-11-16 19:12:26 +0000 UTC", "id-new"),
        ("localhost/fleet-filter-gateway:latest", "2026-11-16 19:12:26 +0000 UTC", "id-new"),
        ("localhost/fleet-filter-gateway:0.1.0-second", "2026-11-15 19:12:26 +0000 UTC", "id-second"),
        ("localhost/fleet-filter-gateway:0.1.0-third", "2026-11-14 19:12:26 +0000 UTC", "id-third"),
        ("localhost/fleet-filter-gateway:0.1.0-fourth", "2026-11-13 19:12:26 +0000 UTC", "id-fourth"),
        ("localhost/fleet-filter-gateway:0.1.0-fifth", "2026-11-12 19:12:26 +0000 UTC", "id-fifth"),
    ]
    created = {"id-new": NOW - 3600, "id-second": NOW - 86400 * 2, "id-third": NOW - 86400 * 3,
               "id-fourth": NOW - 86400 * 4, "id-fifth": NOW - 86400 * 5}
    original = fake_runtime(monkeypatch, images,
                            sizes={k: 263 * 1024 * 1024 for k in created}, created=created)
    try:
        plan = pbh.plan_for_runtime(["podman"], keep=3, min_age_hours=24, now=NOW)
    finally:
        restore(monkeypatch, original)
    untagged = sorted(entry["reference"] for entry in plan["untag"])
    check(untagged == ["localhost/fleet-filter-gateway:0.1.0-fifth",
                       "localhost/fleet-filter-gateway:0.1.0-fourth"],
          "with keep=3 the two oldest versioned tags are untagged", str(untagged))
    check(all("latest" not in ref for ref in untagged),
          "`latest` is never untagged, whatever its timestamp")


def test_unowned_repository_is_untouched():
    """Another project's images are never untagged, even when this project's retention is aggressive."""
    monkeypatch = {}
    images = [
        ("docker.io/library/nginx:1.25", "2026-01-01 00:00:00 +0000 UTC", "nginx-id"),
        ("docker.io/library/nginx:1.24", "2025-12-01 00:00:00 +0000 UTC", "nginx-old"),
        ("docker.io/library/nginx:latest", "2026-01-01 00:00:00 +0000 UTC", "nginx-id"),
    ]
    original = fake_runtime(monkeypatch, images, sizes={"nginx-id": 100, "nginx-old": 100},
                            created={"nginx-id": NOW - 86400 * 300, "nginx-old": NOW - 86400 * 350})
    try:
        plan = pbh.plan_for_runtime(["podman"], keep=1, min_age_hours=24, now=NOW)
    finally:
        restore(monkeypatch, original)
    check(plan["untag"] == [], "no tag of an unowned repository is queued for removal",
          str(plan["untag"]))
    check(plan["remove"] == [],
          "a tagged, unowned image is not removed even when it is old", str(plan["remove"]))


def test_age_floor_and_container_protection():
    """Young dangling images and images a container still references are left alone."""
    monkeypatch = {}
    images = [
        ("<none>:<none>", "2026-11-16 19:00:00 +0000 UTC", "young"),        # 23 minutes old
        ("<none>:<none>", "2026-11-14 19:00:00 +0000 UTC", "old"),          # 2 days old
        ("<none>:<none>", "2026-11-14 19:00:00 +0000 UTC", "in-use"),       # old, but referenced
    ]
    original = fake_runtime(monkeypatch, images,
                            sizes={"young": 10, "old": 20, "in-use": 30},
                            created={"young": NOW - 1200, "old": NOW - 86400 * 2,
                                     "in-use": NOW - 86400 * 2},
                            containers=["in-use"])
    try:
        plan = pbh.plan_for_runtime(["podman"], keep=3, min_age_hours=24, now=NOW)
    finally:
        restore(monkeypatch, original)
    removed = sorted(entry["image"] for entry in plan["remove"])
    check(removed == ["old"],
          "only the old, unreferenced dangling image is removed", str(removed))


def test_image_that_loses_its_last_tag_becomes_removable():
    """Untagging is what makes an image dangling; the plan has to notice, in the right order."""
    monkeypatch = {}
    images = [
        ("localhost/fleet-filter-scanner:0.1.0-new", "2026-11-16 19:12:26 +0000 UTC", "scan-new"),
        ("localhost/fleet-filter-scanner:latest", "2026-11-16 19:12:26 +0000 UTC", "scan-new"),
        ("localhost/fleet-filter-scanner:0.1.0-old", "2026-11-01 19:12:26 +0000 UTC", "scan-old"),
    ]
    original = fake_runtime(monkeypatch, images, sizes={"scan-new": 332 * 1024 * 1024,
                                                        "scan-old": 308 * 1024 * 1024},
                            created={"scan-new": NOW - 3600, "scan-old": NOW - 86400 * 15})
    try:
        plan = pbh.plan_for_runtime(["podman"], keep=1, min_age_hours=24, now=NOW)
    finally:
        restore(monkeypatch, original)
    check([e["reference"] for e in plan["untag"]] == ["localhost/fleet-filter-scanner:0.1.0-old"],
          "the superseded tag is untagged", str(plan["untag"]))
    check([e["image"] for e in plan["remove"]] == ["scan-old"]
          and plan["remove"][0]["reason"] == "dangling after untag",
          "the image that lost its last tag is queued for removal, labelled as such",
          str(plan["remove"]))


def test_disk_usage_shapes():
    """`system df --format json` is a list on podman 5.x and a dict on Docker; both are read."""
    original = pbh.run
    try:
        pbh.run = lambda argv, timeout=120: json.dumps([
            {"Type": "Images", "Total": 329, "RawSize": 5286022249, "Size": "5.286GB"},
            {"Type": "Containers", "Total": 0, "RawSize": 0, "Size": "0B"}])
        check(pbh.disk_usage(["podman"]) == 5286022249,
              "podman 5.x list shape sums RawSize across records")
        pbh.run = lambda argv, timeout=120: json.dumps({"images": {"size": 1234}})
        check(pbh.disk_usage(["docker"]) == 1234, "the Docker dict shape is also read")
        pbh.run = lambda argv, timeout=120: "not json"
        check(pbh.disk_usage(["podman"]) == 0, "unparseable output is 0 rather than a crash")
    finally:
        pbh.run = original


def test_humanize():
    """Byte rendering matches what `podman images` prints closely enough to compare against."""
    check(pbh.humanize(0) == "0B" and pbh.humanize(1024) == "1kB"
          and pbh.humanize(332127633) == "316.7MB",
          "sizes render in the same units podman uses",
          "%s %s %s" % (pbh.humanize(0), pbh.humanize(1024), pbh.humanize(332127633)))


def test_dry_run_is_the_default_and_changes_nothing():
    """Without --apply the tool prints the plan and performs no removals."""
    original = pbh.run
    calls = []

    def spy(argv, timeout=120):
        """Record every podman invocation and answer it with the smallest useful payload."""
        calls.append(list(argv))
        if len(argv) > 1 and argv[1] == "images":
            return "localhost/fleet-filter-gateway:0.1.0-x|2026-11-16 19:12:26 +0000 UTC|idx"
        if len(argv) > 1 and argv[1] in ("ps", "system"):
            return ""
        return ""

    pbh.run = spy
    try:
        out = pbh.main([])
    finally:
        pbh.run = original
    check(out == 0, "a dry run exits 0")
    check(not any("rmi" in call for call in calls), "a dry run never calls rmi", str(calls[:3]))


def main():
    """Run every test function in this module and report the totals."""
    for name in sorted(globals()):
        if name.startswith("test_"):
            globals()[name]()
    print("test_prune_build_host.py: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
