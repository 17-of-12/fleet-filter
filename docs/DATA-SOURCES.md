# Data sources and their licenses

This project reads public vulnerability data. If it is published, every source it touches has to be
one its users may lawfully read, and the reason has to be visible rather than assumed. Licenses below
were read from the source on 2026-11-25, not remembered.

## Used by `bin/cve-triage.py`

| source | license | notes |
|---|---|---|
| NVD (CVE 2.0 API) | US Government work, public domain | rate limited without an API key (5 requests / 30s) |
| CISA KEV | US Government work, public domain | small JSON, daily |
| EPSS (FIRST) | freely and openly accessible; attribution expected | daily CSV or API |

## Used by `bin/poc-index.py`

| source | license | what is taken |
|---|---|---|
| NVD reference tags | public domain | URLs the record itself marks `Exploit` |
| Exploit-DB (`files_exploits.csv`) | **GPL-2.0** (data repository) | exploit id, date, `verified` flag, URL |
| Metasploit module metadata | **BSD-3-Clause** | module names and the CVEs they reference |
| nomi-sec/PoC-in-GitHub | **CC0-1.0** | repository URLs |
| nuclei-templates | **MIT** | template URL; the request inside it is the shape donor |

Nothing here redistributes exploit code. The pipeline stores *references* (ids, URLs, dates) and
derives short literal request shapes from them; an exploit's source code is never copied into this
repository or into a deployed policy.

`--sources` accepts any subset of `nvd,exploitdb,metasploit,pocingithub,nuclei`. A downstream user
who does not want GPL-2.0 data input, or BSD-3-Clause module names, can drop either without touching
code:

```
bin/poc-index.py --cves CVE-2021-41773 --sources nvd,pocingithub,nuclei --out poc.json
```

The default is all five, because each adds a distinct kind of evidence and every one of them permits
this use.

## Deliberately not used

| source | reason |
|---|---|
| Packet Storm | decommissioned RSS 2025-10-23; states programmatic extraction "comes at a cost" and points at a paid API. The NVD exploit tag still gives us the URL, which is provenance rather than a feed. |
| Vulners, Sploitus and similar aggregators | API access is contractual, and their terms are not ones this project can pass on to its users. |
| General code search (GitHub search, grep.app) | not a license problem - a determinism problem. A relevance-ranked result set cannot be replayed, so it cannot be evidence. |
| GitHub Advisory Database | CC-BY-4.0 scraped: permissive, but it covers package ecosystems rather than request-visible bugs, so it is not wired in. Add it if the monitored estate starts serving npm/PyPI artifacts. |

## The rule this establishes

A source is usable here if it either dedicates the data (CC0), licenses it permissively (MIT,
BSD-3, Apache-2.0), or is a government work (public domain), and if a human can point at that fact.
"Everyone else scrapes it" is not a license, and neither is "it was free when we started".
