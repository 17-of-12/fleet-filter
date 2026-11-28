#!/usr/bin/env python3
"""List the web-facing CVEs in a triage window, with the evidence for calling them web-facing.

The triage funnel answers "what can be fired at this estate". This answers a wider question: what
speaks HTTP at all, including software we do not run - because a signature protects whatever
deployment it is installed on, and the next host to be compromised is not always one of ours.

Nothing is inferred silently. Each row says how it was matched: `cpe` means NVD names a product in
config/web-surface.yaml; `keyword` means only the description mentioned HTTP, which is weaker
evidence and is labelled so a reader can discount it; `product` means the CVE names a product that
is not on the declared surface at all, so the row carries no HTTP evidence and is listed only
because the CVE is being exploited.

Columns are the ones that decide whether a row is work: the CVSS access path (AV/PR/UI say whether
an unauthenticated request can reach it), KEV, EPSS, and whether the reference list has code.

Usage:
    bin/web-candidates.py --nvd raw/nvd.json --kev raw/kev.json --epss raw/epss.csv.gz
    bin/web-candidates.py ... --markdown -   # write the report instead of the table (`-` = stdout)
"""

import argparse
import csv
import gzip
import io
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SURFACE = REPO / "config" / "web-surface.yaml"
# Strength of the evidence behind `via`, strongest first: the order rows are reported in.
EVIDENCE_ORDER = {"cpe": 0, "keyword": 1, "product": 2}


def load_surface(path=SURFACE):
    """The declared web surface: product pairs and description keywords."""
    import yaml
    document = yaml.safe_load(Path(path).read_text()) or {}
    products = set()
    for pair in document.get("products") or []:
        vendor, _, product = pair.partition("/")
        products.add((vendor.lower(), product.lower()))
    return products, [k.lower() for k in document.get("keywords") or []]


def load_epss(path):
    """EPSS scores from a csv or csv.gz, keyed by CVE id."""
    raw = Path(path).read_bytes()
    text = gzip.decompress(raw).decode() if raw[:2] == b"\x1f\x8b" else raw.decode()
    rows = csv.DictReader(line for line in io.StringIO(text) if not line.startswith("#"))
    return {row["cve"]: float(row["epss"]) for row in rows}


def vector_row(cve):
    """(AV, PR, UI) from the newest CVSS vector the record carries, or (None, None, None)."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for metric in metrics.get(key) or []:
            data = metric.get("cvssData") or {}
            return data.get("attackVector"), data.get("privilegesRequired"), data.get("userInteraction")
    return None, None, None


def products_in(cve):
    """Every vendor:product pair the record's CPEs mark vulnerable.

    A `vulnerable: false` match exists - a node names a product to exclude it or to bound a range -
    and counting it as evidence labels a row `cpe` for a product the CVE does not affect, which is
    the one thing this label has to stay worth.
    """
    pairs = set()
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", True):
                    continue
                fields = match.get("criteria", "").split(":")
                if len(fields) > 5:
                    pairs.add((fields[3].lower(), fields[4].lower()))
    return pairs


def candidates(cves, kev_ids, epss, surface, keywords, require_surface=False,
               threshold=0.1):
    """Rows for CVEs worth reading, strongest evidence first.

    `require_surface=False` is the default and the important one: a product does not have to be
    pre-declared to appear. Filtering on a taxonomy requires classifying every product in the world,
    which is a job for a human who will never finish it; ranking does not. So the gate is the
    exploitation signal itself - in CISA KEV or at `threshold` EPSS or above - and the CVSS access
    path is carried in the row for a reader to weigh rather than used to filter here. The declared
    surface only decides how a row is *labelled and ordered*.

    `require_surface=True` restores the old gate, for when a narrow answer is what is wanted.
    """
    products, rows = surface, []
    for cve in cves:
        description = (cve.get("descriptions") or [{}])[0].get("value", "")
        pairs = products_in(cve)
        named = sorted(pairs & products)
        via = "cpe" if named else ""
        detail = ", ".join("%s/%s" % pair for pair in named)
        if not named:
            lowered = description.lower()
            hit = next((k for k in keywords if k in lowered), "")
            if hit:
                via, detail = "keyword", hit
            elif require_surface:
                continue
            else:
                via = "product"
                detail = ", ".join("%s/%s" % pair for pair in sorted(pairs)) or "(no CPE)"
        av, pr, ui = vector_row(cve)
        # The gate that needs no taxonomy: is anyone actually using this? A product list has to be
        # complete to work; "in KEV or scoring high" works for a product nobody has classified yet.
        if not require_surface:
            score = epss.get(cve["id"], 0.0)
            if cve["id"] not in kev_ids and score < threshold:
                continue
        rows.append({
            "id": cve["id"], "via": via, "product": detail,
            "av": av or "-", "pr": pr or "-", "ui": ui or "-",
            "kev": cve["id"] in kev_ids, "epss": round(epss.get(cve["id"], 0.0), 4),
            "description": " ".join(description.split())[:110],
        })
    # Strongest evidence first, then the order in which a person should pick the next thing to write
    # a signature for: a CPE on the declared surface, then a keyword-only match, then a product
    # nothing declared; within a tier, KEV, then a network path with no privileges, then EPSS.
    rows.sort(key=lambda r: (EVIDENCE_ORDER.get(r["via"], len(EVIDENCE_ORDER)), not r["kev"],
                             r["av"] != "NETWORK", r["pr"] not in ("NONE", "LOW", "-"), -r["epss"]))
    return rows


def table(rows):
    """Fixed-width table for a terminal."""
    header = "%-16s %-7s %-22s %-8s %-6s %-4s %-6s %s" % (
        "CVE", "via", "product / keyword", "AV", "PR", "KEV", "EPSS", "summary")
    out = [header, "-" * len(header)]
    for row in rows:
        out.append("%-16s %-7s %-22s %-8s %-6s %-4s %-6.3f %s" % (
            row["id"], row["via"], row["product"][:22], row["av"], row["pr"],
            "yes" if row["kev"] else "", row["epss"], row["description"]))
    return "\n".join(out)


def markdown(rows, generated):
    """A report a person can read without the terminal."""
    cpe = [r for r in rows if r["via"] == "cpe"]
    keyword = [r for r in rows if r["via"] == "keyword"]
    product = [r for r in rows if r["via"] == "product"]
    unauthenticated = [r for r in rows if r["av"] == "NETWORK" and r["pr"] in ("NONE", "LOW", "-")]
    out = [
        "# Web-facing CVEs%s" % (" (%s)" % generated if generated else ""),
        "",
        "%d records in the window carry an exploitation signal: **%d** speak HTTP by a CPE in "
        "`config/web-surface.yaml`, **%d** matched the HTTP keywords in a description only, and "
        "**%d** name a product that is not on the declared surface, so they carry no HTTP evidence "
        "at all." % (len(rows), len(cpe), len(keyword), len(product)),
        "",
        "Of those, **%d** are reachable by an unauthenticated network request (AV:N with PR:N or "
        "PR:L), and **%d** are in CISA KEV." % (
            len(unauthenticated), sum(1 for r in rows if r["kev"])),
        "",
        "## By CPE",
        "",
        "| CVE | product | AV | PR | KEV | EPSS | summary |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in cpe:
        out.append("| %s | %s | %s | %s | %s | %.3f | %s |" % (
            row["id"], row["product"], row["av"], row["pr"], "yes" if row["kev"] else "",
            row["epss"], row["description"].replace("|", "/")))
    out += ["", "## By description keyword only", "",
            "Weaker evidence: the phrase matched, the bug may not be reachable over HTTP.", "",
            "| CVE | keyword | AV | PR | KEV | EPSS | summary |",
            "|---|---|---|---|---|---|---|"]
    for row in keyword:
        out.append("| %s | %s | %s | %s | %s | %.3f | %s |" % (
            row["id"], row["product"], row["av"], row["pr"], "yes" if row["kev"] else "",
            row["epss"], row["description"].replace("|", "/")))
    return "\n".join(out) + "\n"


def main(argv=None):
    """CLI entry point: read a window, print the candidates."""
    parser = argparse.ArgumentParser(description="List web-facing CVEs in a triage window")
    parser.add_argument("--nvd", required=True, help="saved NVD response")
    parser.add_argument("--kev", help="saved KEV catalogue")
    parser.add_argument("--epss", help="saved EPSS csv or csv.gz")
    parser.add_argument("--surface", default=str(SURFACE))
    parser.add_argument("--markdown", metavar="PATH",
                        help="write a markdown report instead of a table; `-` prints it to stdout")
    parser.add_argument("--json", metavar="PATH",
                        help="write the candidates in the work-queue shape, for candidate-review")
    parser.add_argument("--generated", default="", help="window label for the report title")
    parser.add_argument("--require-surface", action="store_true",
                        help="only list products declared in config/web-surface.yaml")
    args = parser.parse_args(argv)

    document = json.loads(Path(args.nvd).read_text())
    cves = [item.get("cve", item) for item in
            (document.get("vulnerabilities", document) if isinstance(document, dict) else document)]
    kev_ids = set()
    if args.kev:
        kev_ids = {e["cveID"] for e in json.loads(Path(args.kev).read_text())["vulnerabilities"]}
    epss = load_epss(args.epss) if args.epss else {}

    surface, keywords = load_surface(args.surface)
    rows = candidates(cves, kev_ids, epss, surface, keywords, args.require_surface)
    if args.json:
        # The same shape bin/cve-triage.py emits, so the review stage accepts either source without a
        # translation step that would drift from one of them.
        Path(args.json).write_text(json.dumps({"generated_at": args.generated or None,
                                               "queue": rows}, indent=2) + "\n")
        print("web-candidates: %d row(s) written to %s" % (len(rows), args.json))
    elif args.markdown == "-":
        sys.stdout.write(markdown(rows, args.generated))
    elif args.markdown:
        Path(args.markdown).write_text(markdown(rows, args.generated))
        print("web-candidates: %d row(s) written to %s" % (len(rows), args.markdown))
    else:
        print(table(rows))
        print("\n%d record(s); %d in KEV; %d unauthenticated network-reachable" % (
            len(rows), sum(1 for r in rows if r["kev"]),
            sum(1 for r in rows if r["av"] == "NETWORK" and r["pr"] in ("NONE", "LOW", "-"))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
