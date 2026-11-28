# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0, a breaking change to the policy schema or the detection store bumps the minor version; the
project will not cut a 1.0 until the policy format has survived a release without a schema change.

## [Unreleased]

## [0.2.0] - 2026-11-28
### Added

- **Coverage no longer depends on enumerating software.** Estate entries declare a product by name:
  `any_version` marks a product whose patch level is a point in time rather than a fact, so a CVE for
  a version the host has not shipped yet is still a candidate. Hits are labelled `cpe-any-version`.
- **A second question, answered separately.** `bin/web-candidates.py` and `config/web-surface.yaml`
  list what speaks HTTP, including products the estate does not run. The default gate is the
  exploitation signal itself - KEV listed, or an EPSS score at or above the threshold - so a local or
  authenticated KEV CVE is still a candidate; the attack-vector attributes are reported, not required.
  Declared products are labelled and ordered first instead of gating the list.
- **A decision stage between a signal and exploit work.** `bin/candidate-review.sh` has a session
  accept or reject each candidate against five closed reason codes, records both outcomes with a
  timestamp, and treats an unanswered candidate as missing rather than accepted. Accepted items are
  written in the queue format the worker already reads; rejects never reach `blocked/`, which means
  "tried and failed". `--replay` reuses recorded decisions, so the stage is testable and a judgement
  survives a lost queue directory.
- **Per-application runbooks.** `lab/apps/<application>.md` carries what the generic procedure cannot:
  build commands, preconditions the image does not ship, the request that proves a victim vulnerable
  and its negative control, and the walls earlier sessions hit. The worker prompt requires reading one
  before building and updating it before stopping, success or failure.
- **A six-hourly ops watch** (`bin/ops-watch.py`) recording timer, queue, pull-request, drift and disk
  state; it repairs only an inactive unit it manages.
- **A weekly repository security audit** (`bin/github-audit.py`): eight settings read from the API
  fields that carry them, with a timer, because settings drift silently.
- Public exporter that derives a publishable tree, rewrites estate identifiers, and refuses to emit
  one containing a forbidden token.
- Signed policy distribution: a detached RSA signature over each digest, verified on the host with a
  key provisioned out of band, before the policy is parsed or installed.
- `bin/exploit-upstream.py`, and its gate: a contribution is complete only when the signature, the
  verdict and a publishable recorded run are all present.
- `bin/dependabot-check.py`: a deterministic verdict for dependency-bump pull requests. It accepts a
  diff only when every changed line is a version pin and every pin added is a pin removed, so
  dependabot stops needing an agent session it could never be given; exit codes separate "clean" from
  "refused" from "could not run". The review queue gained the matching `machine` mode and
  `bin/publish-review.py` gained `--machine`, which labels a verdict as machine-produced instead of
  pretending three roles reviewed it.
- CI: the repository gate runs on every push and pull request, and fails a tree that only passes
  with a dirty working copy.
- MIT license, security policy, contribution guide and issue templates.

### Changed

- `bin/prs-needing-review.py` admits `dependabot[bot]` as an author (on a `dependabot/*` branch only)
  and applies its failure backoff to every mode that would redo work, not only to `review`: the queue
  stops at the lowest eligible number, so a bump refused once used to block every pull request behind it.
- The CVE check runs every four hours instead of nightly, with timestamped run directories and KEV/EPSS
  cached for six hours. Deferred CVEs are recorded and re-checked rather than dropped when they age out
  of the triage window.
- `bin/publish-review.py` deletes the merged `release/` branch on both merge paths, so a merge posted
  through the verdict path stops leaving the branch behind; the guard accepts only `release/` refs, so
  `main` and dependency branches cannot be deleted by it.
- Request bodies have an aggregate memory budget, not only a per-request cap.
- `X-Forwarded-For` is read from every header, right to left, so a client cannot name the address
  the gateway judges.
- Policy fetch refuses an unsigned digest unless explicitly allowed.
- The README leads with the problem the project solves rather than with its directory layout.

### Fixed

- The renderer's default spool directory was outside the gateway unit's writable paths, so detections
  were written nowhere under `ProtectSystem=strict`.
- A newline in a bypass reason could inject a map entry and disable enforcement.
- The responder accepted a claim signature from any client, so the traffic source could write the
  assertion that decided its own quarantine.
- `https://` backends were accepted by the policy parser although no upstream TLS connector exists.
- `max_connections_per_source = 0` refused every connection instead of meaning unlimited.

## [0.1.0] - 2026-11-25

First public release.

### Added

- Rust reverse proxy: HTTP/1.1 and HTTP/2 inbound, HTTP/1.1 outbound, request-shape detection,
  bounded body-marker inspection, quarantine map with hot reload, and a bounded deception response.
- Three deployment topologies (`edge-tls`, `behind-lb-plain`, `behind-lb-tls`) rendered from the
  signature store and validated with the gateway's own parser.
- Signature store with per-variant provenance and test fixtures; a renderer that projects it into
  each enforcement point.
- Exploit evidence ledger: an attack is only `blocked` once it was shown working without the control
  and failing through it, with the recorded run committed next to the claim.
- Daily CVE triage: NVD, KEV and EPSS through an inventory of the estate, producing a ranked queue
  and a delta against the previous run.
