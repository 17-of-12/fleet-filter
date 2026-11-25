#!/usr/bin/env python3
"""Assemble reference-code evidence for the CVEs the triage funnel decided matter.

This answers "does public exploit code exist for this record", which is the difference between a
triage queue and a worklist. It is an assembler, not a search: each source below is a curated index
with a stable URL or a stable file, so the answer is reproducible and attributable. Nothing here
queries a general code search, because a result set ordered by relevance is not evidence that can be
replayed or argued with.

Sources, in the order their evidence is trusted:

  1. `nvd`          a reference the NVD record itself tags `Exploit`. This arrives with the CVE pull,
                    costs nothing, and is the only source that cannot disagree with the record.
  2. `exploitdb`    the canonical Exploit-DB `files_exploits.csv`: an assigned ID, a published date,
                    and a `verified` flag. A verified entry is a maintainer having run it.
  3. `metasploit`   a module whose references name the CVE. A framework module implies a supported,
                    repeatable exploit rather than a one-off write-up.
  4. `pocingithub`  nomi-sec/PoC-in-GitHub's per-CVE index of public repositories. Broadest coverage,
                    weakest curation: a repository existing is not a repository working.
  5. `nuclei`       a template in projectdiscovery/nuclei-templates. Distinct from the others because
                    it carries the *request* as data - the shape the next stage wants.

The output ranks by that order and records which source said what, so "we have a PoC" is never a
single undifferentiated boolean. Coverage differs per source and is printed on every run.

Usage:
    poc-index.py --queue data/triage/2026-11-25/queue.json --fetch --out data/triage/2026-11-25/poc.json
    poc-index.py --cves CVE-2021-41773 --offline --cache data/cache
"""

import argparse
import csv
import io
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

EXPLOITDB = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
POCINGITHUB = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/%s/%s.json"
NUCLEI = ("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/"
          "http/cves/%s/%s.yaml")
METASPLOIT = ("https://raw.githubusercontent.com/rapid7/metasploit-framework/master/"
              "db/modules_metadata_base.json")
NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s"

# Evidence quality, best first. Used for ordering and for the "best source" column.
ORDER = ("nvd", "exploitdb", "metasploit", "pocingithub", "nuclei")


def fetch(url, timeout=120, attempts=3):
    """Download a URL, retrying transient failures; None when the resource does not exist."""
    last = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            last = error
        except (urllib.error.URLError, OSError) as error:
            last = error
        if attempt + 1 < attempts:
            import time
            time.sleep(2 * (attempt + 1))
    raise SystemExit("fetch failed for %s: %s" % (url, last))


def cached(url, cache_dir, name):
    """Return the bytes for `url`, keeping one copy on disk so a re-run need not re-download."""
    path = Path(cache_dir) / name
    if path.exists():
        return path.read_bytes()
    body = fetch(url)
    if body is None:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return body


def from_nvd(cve_record):
    """References the NVD record itself tags as exploits."""
    urls = [
        reference["url"]
        for reference in cve_record.get("references", [])
        if "Exploit" in reference.get("tags", [])
    ]
    return {"source": "nvd", "urls": sorted(set(urls))}


def load_exploitdb(raw):
    """Map CVE id -> Exploit-DB entries, from the canonical CSV's `codes` column."""
    table = {}
    reader = csv.DictReader(io.StringIO(raw.decode(errors="replace")))
    for row in reader:
        codes = (row.get("codes") or "").replace(";", ",")
        for code in codes.split(","):
            code = code.strip()
            if code.upper().startswith("CVE-"):
                table.setdefault(code.upper(), []).append({
                    "id": row.get("id"),
                    "description": (row.get("description") or "")[:120],
                    "verified": row.get("verified") == "1",
                    "url": "https://www.exploit-db.com/exploits/%s" % row.get("id"),
                })
    return table


def load_metasploit(raw):
    """Map CVE id -> module names, from the framework's module metadata."""
    table = {}
    try:
        modules = json.loads(raw)
    except json.JSONDecodeError:
        return table
    for name, meta in modules.items():
        for reference in meta.get("references", []) or []:
            if isinstance(reference, str) and reference.upper().startswith("CVE-"):
                table.setdefault(reference.upper(), []).append(name)
    return table


def pocingithub_for(cve_id, cache_dir, online):
    """Repository URLs from nomi-sec/PoC-in-GitHub, whose per-CVE paths are predictable."""
    year = cve_id.split("-")[1]
    body = (cached(POCINGITHUB % (year, cve_id), cache_dir, "pocingithub-%s.json" % cve_id)
            if online else None)
    if not body:
        return []
    try:
        entries = json.loads(body)
    except json.JSONDecodeError:
        return []
    return sorted(entry["html_url"] for entry in entries if entry.get("html_url"))


def nuclei_for(cve_id, cache_dir, online):
    """Whether a template exists, and where. The template carries the request as data."""
    year = cve_id.split("-")[1]
    url = NUCLEI % (year, cve_id)
    body = cached(url, cache_dir, "nuclei-%s.yaml" % cve_id) if online else None
    if not body:
        return None
    return url


def evidence_for(cve_id, nvd_record, tables, cache_dir, online, allowed=ORDER):
    """All evidence for one CVE, in trust order, with the source that provided each fact."""
    found = {}

    nvd = from_nvd(nvd_record) if nvd_record and "nvd" in allowed else {"urls": []}
    if nvd["urls"]:
        found["nvd"] = nvd["urls"]

    exploitdb = tables["exploitdb"].get(cve_id.upper(), []) if "exploitdb" in allowed else []
    if exploitdb:
        found["exploitdb"] = exploitdb

    metasploit = tables["metasploit"].get(cve_id.upper(), []) if "metasploit" in allowed else []
    if metasploit:
        found["metasploit"] = sorted(metasploit)

    if online and "pocingithub" in allowed:
        repos = pocingithub_for(cve_id, cache_dir, online)
        if repos:
            found["pocingithub"] = repos
        template = nuclei_for(cve_id, cache_dir, online) if "nuclei" in allowed else None
        if template:
            found["nuclei"] = [template]

    best = next((source for source in ORDER if source in found), None)
    count = sum(len(value) for value in found.values())
    return {"cves": {cve_id: {"best": best, "count": count, "sources": found}}}


def main(argv=None):
    """Command line entry point: read a triage queue or explicit CVEs, write the evidence map."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--queue", help="a queue.json from cve-triage.py")
    parser.add_argument("--cves", help="comma-separated CVE ids instead of a queue")
    parser.add_argument("--nvd-json", help="the NVD snapshot the queue was built from")
    parser.add_argument("--cache", default=str(REPO / "data" / "cache"), help="download cache")
    parser.add_argument("--offline", action="store_true", help="use only cached and local sources")
    parser.add_argument(
        "--sources",
        default=",".join(ORDER),
        help="comma-separated subset of %s; a downstream user can drop any of them"
             % ",".join(ORDER),
    )
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    allowed = {name.strip() for name in args.sources.split(",") if name.strip()}
    unknown = allowed - set(ORDER)
    if unknown:
        parser.error("unknown source(s): %s; choose from %s"
                     % (", ".join(sorted(unknown)), ", ".join(ORDER)))

    if args.queue:
        raw = json.loads(Path(args.queue).read_text())
        cves = [item["id"] for item in raw["queue"]]
        # The queue file carries the digest, not the records; the snapshot is where tags live.
        nvd_path = Path(args.queue).parent / "raw" / "nvd.json"
    elif args.cves:
        cves = [part.strip() for part in args.cves.split(",") if part.strip()]
        nvd_path = Path(args.nvd_json) if args.nvd_json else None
    else:
        parser.error("one of --queue or --cves is required")

    nvd_records = {}
    if not nvd_path and not args.offline:
        # `--cves` without a snapshot: the record still has to be read, because the NVD exploit tag
        # is the cheapest and most authoritative source and skipping it would understate evidence.
        for cve_id in cves:
            body = cached(NVD_CVE % cve_id, args.cache, "nvd-%s.json" % cve_id)
            if body:
                try:
                    nvd_records[cve_id] = json.loads(body)["vulnerabilities"][0]["cve"]
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue
    if nvd_path and nvd_path.exists():
        for item in json.loads(nvd_path.read_text()).get("vulnerabilities", []):
            nvd_records[item["cve"]["id"]] = item["cve"]

    tables = {"exploitdb": {}, "metasploit": {}}
    if not args.offline and "exploitdb" in allowed:
        exploitdb_raw = cached(EXPLOITDB, args.cache, "files_exploits.csv")
        if exploitdb_raw:
            tables["exploitdb"] = load_exploitdb(exploitdb_raw)
    if not args.offline and "metasploit" in allowed:
        metasploit_raw = cached(METASPLOIT, args.cache, "modules_metadata_base.json")
        if metasploit_raw:
            tables["metasploit"] = load_metasploit(metasploit_raw)

    result = {"cves": {}}
    for cve_id in cves:
        result["cves"].update(
            evidence_for(cve_id, nvd_records.get(cve_id), tables, args.cache,
                        not args.offline, allowed)["cves"]
        )

    Path(args.out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    counts = {}
    for entry in result["cves"].values():
        for source in entry["sources"]:
            counts[source] = counts.get(source, 0) + 1
    print("%d CVE(s) examined" % len(result["cves"]))
    for source in ORDER:
        print("  %-12s %d" % (source, counts.get(source, 0)))
    with_code = sum(1 for entry in result["cves"].values() if entry["count"])
    print("with reference code: %d of %d" % (with_code, len(result["cves"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
