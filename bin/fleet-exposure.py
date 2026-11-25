#!/usr/bin/env python3
"""Turn a Fleet-Filter host sweep into the fleet exposure record.

Purpose
-------
K2's deliverable is not "we ran a sweep" - it is a machine-readable answer to *which
hosts run Apache, at which version, with which modules, and whether that version is
actually exposed*. A sweep emits per-host text; this converts it into one JSON document
with the CVE classification applied, so a later session can query the fleet instead of
re-reading a log.

What the host list is NOT
-------------------------
The set of hosts to probe comes from *our* registry (`web/installs.yaml`), never from
another project's inventory. The 2026-11-14 sweep was run over
`~/projects/ansible-estate/inventories/production/hosts.yaml` and recorded that path
verbatim, which answered "what does Ansible know about" instead of "what do we own" -
132 hosts measured when the project owns two. Owner ruling 2026-11-20: the Ansible
inventory is not a data source this project gets. The source is now an explicit argument
so the provenance in the output is a fact the caller supplied, not a hard-coded default
pointing at somebody else's file.

Why the classification is separate from the probe
-------------------------------------------------
The owner's rule is explicit: do not infer vulnerability from an upstream version number
alone, because vendors backport. So this script applies the *documented affected ranges*
for CVE-2026-119618 (httpd 2.4.55-2.4.70 with mod_h2 2.0.8-2.0.42) and labels the result
`in_upstream_range`, which is a claim about the version string - not a claim that the
vendor shipped the fix. `vendor_patch_unverified` stays true on every classification so
the record cannot be misread as a patch audit.

Scope limit worth stating: hosts that were UNREACHABLE are recorded as `unreachable`,
not as `not-installed`. Conflating those two is how an inventory silently loses half the
fleet.
"""

import datetime
import json
import os
import re
import sys

# Documented affected ranges for CVE-2026-119618 (see data/research/cve-2026-119618-2026-11-12.md).
AFFECTED_HTTPD_MIN = (2, 4, 55)
AFFECTED_HTTPD_MAX = (2, 4, 70)
AFFECTED_MODH2_MIN = (2, 0, 8)
AFFECTED_MODH2_MAX = (2, 0, 42)

# Ansible's `-o` line is `host | STATUS => {...}`. Every status verb has to be listed:
# the first sweep silently dropped 12 Windows hosts that report `FAILED!` (winrm module
# missing) because only UNREACHABLE/CHANGED/OK were matched, and a dropped host is worse
# than a failed one because nothing in the report says it was ever there.
HOST_LINE = re.compile(r"^(\S+)\s+\|\s+(UNREACHABLE!|FAILED!|CHANGED|OK)(.*)$", re.S)
# `user@host: message` is how ssh reports an authentication failure for a host that
# overrides ansible_user; it has no pipe, so it needs its own pattern.
AUTH_LINE = re.compile(r"^([^@\s]+)@([^:\s]+):\s+(.*)$")
# Values must not contain a pipe (the probe strips them); the earlier class `[^|\\r]`
# accidentally excluded the letter `r` as well, which truncated "Permissive" to "Pe".
PROBE = re.compile(
    r'os=(?P<os>[^|]*)\|httpd=(?P<httpd>[^|]*)\|httpd_ver=(?P<httpd_ver>[^|]*)\|'
    r'h2=(?P<h2>[^|]*)\|h2_ver=(?P<h2_ver>[^|]*)\|ssl=(?P<ssl>[^|]*)\|'
    r'ports=(?P<ports>[^|]*)(?:\|selinux=(?P<selinux>[^"\\]*))?'
)


def parse_version(version):
    """Turn a version string like `2.4.62` into the tuple (2, 4, 62).

    Takes the version field the probe read from rpm rather than reconstructing it from an
    nvra: `httpd-2.4.62-13.0.1.el9_8.9` cannot be split reliably by regex, and the first
    version of this script mis-parsed it as version `13.0.1`, which silently moved build01
    out of the affected range. Non-numeric trailing segments stop the parse.
    """
    if not version or version in ("none", "-"):
        return None
    parts = []
    for chunk in version.strip().split("."):
        digits = re.match(r"\d+", chunk)
        if not digits:
            break
        parts.append(int(digits.group(0)))
    return tuple(parts) if parts else None


def classify(httpd_nvra, httpd_ver, h2_nvra, h2_ver):
    """Classify one host against the documented CVE ranges.

    Returns a short code. `no_apache` and `apache_without_modhttp2` are deliberate: a host
    without mod_http2 cannot be exploited through mod_http2 at all, which is a different
    fact from "installed but outside the affected range".
    """
    if httpd_nvra in ("none", "", None):
        return "no_apache"
    if h2_nvra in ("-", "", None):
        return "apache_without_modhttp2"
    httpd_v = parse_version(httpd_ver) or parse_version(httpd_nvra)
    h2_v = parse_version(h2_ver) or parse_version(h2_nvra)
    if httpd_v is None or h2_v is None:
        return "unparsable_version"
    httpd_in = AFFECTED_HTTPD_MIN <= httpd_v <= AFFECTED_HTTPD_MAX
    h2_in = AFFECTED_MODH2_MIN <= h2_v <= AFFECTED_MODH2_MAX
    if httpd_in and h2_in:
        return "in_upstream_range"
    if httpd_in and not h2_in:
        return "httpd_in_range_modhttp2_out"
    return "out_of_upstream_range"


def parse_sweep(path):
    """Parse ansible `-o` stdout into one record per host.

    Handles the three shapes a real sweep produces: `host | CHANGED => {json}` (probed),
    `host | UNREACHABLE!: ...` (ssh connect failed), and `user@host: Permission denied`
    (ssh auth failed for a host that overrides ansible_user). `host | FAILED!` covers
    Windows inventory entries, which the shell probe cannot service.
    """
    records = []
    with open(path, "r") as handle:
        content = handle.read()

    for line in content.splitlines():
        if not line.strip():
            continue
        match = HOST_LINE.match(line)
        if not match:
            auth = AUTH_LINE.match(line.strip())
            if auth:
                records.append({
                    "host": auth.group(2),
                    "status": "auth_failed",
                    "detail": auth.group(3)[:200],
                })
            continue

        host, status, rest = match.group(1), match.group(2), match.group(3)
        host = host.split("@")[-1].rstrip(":")
        if status.startswith("UNREACHABLE"):
            records.append({"host": host, "status": "unreachable",
                            "detail": rest.strip().lstrip("!").strip()[:200]})
            continue
        if status.startswith("FAILED"):
            # Windows inventory entries and other non-POSIX targets: the shell probe
            # cannot run, so the host is known-but-uninspectable rather than absent.
            message = rest.strip()
            winrm = "winrm" in message
            records.append({
                "host": host,
                "status": "failed",
                "detail": message[:200],
                "probable_platform": "windows" if winrm else "other",
            })
            continue

        cleaned = rest.replace("\\r", "").replace("\\n", "")
        probe = PROBE.search(cleaned)
        if not probe:
            records.append({"host": host, "status": "no_probe_output", "detail": cleaned[:200]})
            continue

        fields = probe.groupdict()
        record = {
            "host": host,
            "status": "ok",
            "os": fields["os"].strip(),
            "httpd": fields["httpd"].strip(),
            "httpd_version": fields["httpd_ver"].strip(),
            "mod_http2": fields["h2"].strip(),
            "mod_http2_version": fields["h2_ver"].strip(),
            "mod_ssl": fields["ssl"].strip(),
            "listening_ports": [p for p in fields["ports"].strip().split(",") if p and p != "none"],
            "selinux": (fields.get("selinux") or "n/a").strip(),
        }
        record["cve_2026_119618"] = classify(
            record["httpd"], record["httpd_version"], record["mod_http2"], record["mod_http2_version"]
        )
        record["vendor_patch_unverified"] = True
        records.append(record)
    return records


def summarise(records):
    """Collapse the records into the counts a reviewer actually reads first.

    Splitting reachable from inventory_total is the point: a sweep that inspects 10 of
    132 hosts must not be reported as a fleet-wide result, so every non-ok status keeps
    its own bucket instead of disappearing.
    """
    summary = {
        "inventory_total": len(records),
        "probed": sum(1 for r in records if r["status"] == "ok"),
        "unreachable": sum(1 for r in records if r["status"] == "unreachable"),
        "auth_failed": sum(1 for r in records if r["status"] == "auth_failed"),
        "failed_other": sum(1 for r in records if r["status"] == "failed"),
        "no_probe_output": sum(1 for r in records if r["status"] == "no_probe_output"),
        "by_cve_classification": {},
        "by_os": {},
    }
    for record in records:
        if record["status"] != "ok":
            continue
        code = record.get("cve_2026_119618", "unknown")
        summary["by_cve_classification"][code] = summary["by_cve_classification"].get(code, 0) + 1
        summary["by_os"][record["os"]] = summary["by_os"].get(record["os"], 0) + 1
    return summary


def main(argv=None):
    """Read a sweep file and write `data/results/fleet-httpd-exposure-<date>.json`.

    Writes next to the rest of the project's measured evidence rather than to /tmp, so
    the result is versioned with the repo and a future session can diff fleet state over
    time instead of re-running the sweep to remember it.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inventory = os.path.join(repo_root, "web", "installs.yaml")
    method = "bin/fleet-probe.sh (read-only)"
    positional = []
    while argv:
        flag = argv.pop(0)
        if flag == "--inventory":
            inventory = argv.pop(0)
        elif flag == "--method":
            method = argv.pop(0)
        else:
            positional.append(flag)
    sweep = positional[0] if positional else None
    if not sweep or not os.path.exists(sweep):
        sys.stderr.write(
            "usage: fleet-exposure.py [--inventory PATH] [--method TEXT] <sweep-output>\n"
        )
        return 2

    records = parse_sweep(sweep)
    document = {
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_sweep": os.path.basename(sweep),
        "inventory": inventory,
        "method": method,
        "cve": "CVE-2026-119618",
        "classification_note": (
            "in_upstream_range means the installed version string falls inside the "
            "documented affected ranges. It is not a patch audit: Oracle backports fixes "
            "without bumping the version, so vendor errata must be checked before any "
            "host is called vulnerable."
        ),
        "summary": summarise(records),
        "hosts": records,
    }

    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "results")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(
        out_dir, "fleet-httpd-exposure-%s.json" % datetime.date.today().isoformat()
    )
    with open(out_path, "w") as handle:
        json.dump(document, handle, indent=2, sort_keys=False)
        handle.write("\n")

    print("wrote %s" % out_path)
    print(json.dumps(document["summary"], indent=2))
    return 0


if __name__ == "__main__":
    # Pass the real argv explicitly: `main()` takes argv as a parameter so the tests and
    # this entry point share one code path, and calling it with no argument used to fall
    # through to the usage message instead of reading sys.argv.
    sys.exit(main(sys.argv[1:]))
