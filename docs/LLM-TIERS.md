# Model tiers, and where a model is allowed to touch this project

Owner directive 2026-11-24: use every tier we need - small, medium, big - but keep the deterministic
levers authoritative. The reason to tier is not cost alone; it is that a signature written by a model
is **untrusted input** until a deterministic gate says otherwise, exactly like a request from the
internet.

## The one hard boundary

**No model in the runtime path.** Detection, classification, quarantine, rendering and expiry are
pure functions over files in the tree (rule 26). A model may *write* those files during development;
nothing may *call* a model while deciding whether to tarpit a client. If a design ever needs an
inference at request time, the answer is to precompute its output into a table at build time.

Everything below is about build time.

## The tiers

| Tier | Who | Does | Called | Cost |
|---|---|---|---|---|
| **T0** | no model | run gates, replay fixtures, render artifacts, promote a signature, reconcile a manifest | every change | ~0 |
| **T1** small local (single-slot, seconds) | crank | classify a failing gate, apply a table-driven edit, update a manifest row, summarise a log, draft a commit message | every turn | near zero |
| **T2** medium local (120B class) | journeyman | routine code in an established pattern, signature variants from a template, review of a small diff, test authoring for a known invariant | per task | cheap |
| **T3** big, frontier (remote API) | specialist | read unfamiliar exploit code and name the request it sends; reason about a new protocol edge; write a new invariant or a new subsystem; adversarial review of a security claim | when escalated, batched, asynchronous | metered |

The tiers are not a hierarchy of quality - they are a hierarchy of **novelty per token**. T3 is for
work where the input is unknown; T2 is for work where the shape is known and the content varies; T1
is for work where both are known.

## The pipeline that matters: PoC to protocol filter

A zero-day's window is the time between the PoC appearing and the package being patched. The product
must turn PoC code into an enforcement artifact faster than a human can read it, and the model is the
part that reads - so the pipeline is designed to make the reading the *only* thing the model does.

```
 1  ACQUIRE     T0   fetch the PoC, archive bytes under data/research/poc/<cve>/, record URL+date+sha256
 2  EXTRACT     T3   read the PoC; name the request (method, target, headers, body, protocol shape)
 3  DRAFT       T3/T2 fill a signature row: variants, match fields, vuln_layer, response profile,
                    provenance, fp_guard, TTL - the schema already exists and is not optional
 4  REPLAY      T0   fire each variant against the live victim: must match, and must be *recorded*
 5  CONTROL     T0   fire the same bytes against a non-victim: must not match
 6  BYPASS      T0   run the normalization corpus (`//`, `/./`, `%2e`, `;`, case, double-encode):
                    the signature must still match the request it claims to cover
 7  BLAST       T0   `bin/sigtest.py` replay against historical logs: how many sources would this have
                    quarantined last week, and does it touch the monitoring traffic
 8  RENDER      T0   signatures.yaml -> tarpit-signatures.conf + gateway [detection] table, hashed
 9  PROMOTE     T0   commit with the artifact hash and the evidence file; review_by date recorded
```

Steps 1 and 4-9 are already deterministic machinery in this repo (`render-signature-rules.py`,
`render-gateway-detection.py`, `sigtest.py`, the fixture-based `test_signatures.py`). Step 2 and 3 are
where a frontier model earns its cost, and step 3 is deliberately schema-bound so the model's freedom
is "which fields", not "what format".

The rule for step 4: **a signature that has not been fired at a live victim is a hypothesis**, and a
signature that has not been fired at a control is a liability. `data/results/lab-victims-2026-11-24.md`
is the first pair that satisfies this, for CVE-2021-41773, with the same request returning 200 on the
victim and 400 on the control.

## When to escalate

A tier escalates when the task's *input* is unknown, not when it is hard. Concretely, escalate to T3
when any of these is true:

1. **Unfamiliar code.** The PoC is in a language, framework or protocol we have not handled before.
2. **A new invariant.** The work would add a rule that other code must obey (not a row in a table).
3. **Contradiction.** Two sources disagree (vendor advisory vs PoC, PoC vs observed traffic) and the
   resolution changes enforcement.
4. **Adversarial review.** Someone must argue *against* a security claim rather than implement it.
5. **Protocol novelty.** The request cannot be expressed in the existing schema without extending it.

Everything else is T1/T2. The failure mode to avoid is a small model grinding on an unfamiliar PoC for
twenty turns and producing a plausible signature that matches the fixture it was written against -
which is the self-referential failure this project has already paid for twice.

## What makes a model's output trustworthy here

The model is not trusted; the gate is. Every model-authored artifact carries:

* **Provenance the gate checks.** `source:` must be a URL that was fetched at draft time, archived
  under `data/research/poc/`, with the sha256 of the bytes read. A signature whose source cannot be
  re-read is folklore and the renderer's provenance rule rejects it.
* **Positives from the wire, not from prose.** The `tests.positive` entries are the exact request
  lines the model claims the exploit sends; step 5 proves they came from the PoC and not from the
  model's imagination by firing them at a real binary.
* **Negatives that look like the exploit.** A near-miss URI, a GET where the exploit is a POST, the
  same path with a different version - the `fp_guard` entries exist so a broad pattern fails loudly.
* **A blast radius number.** Step 7 answers "how many addresses would this quarantine", because a
  signature that matches everything is a self-inflicted outage.
* **A review date.** `review_by:` is part of the schema; a signature nobody re-reads after the patch
  ships is a rule that only fires on noise.

## Cost shape that makes the tiers usable

* **Batch the frontier calls.** A disclosure day produces N variants; one T3 call with the PoC and the
  schema returns all candidates, then T0 sorts them. Ten small calls cost more than one big one and
  produce less coherent variants.
* **Keep the context small on purpose.** The T3 prompt is the PoC, the schema, two existing rows as
  examples and the victim's current log format - not the repository. Everything else is fetched by
  T0 after the model has produced a draft.
* **Let T1 do the paperwork.** Commit messages, manifest rows, tracker updates and evidence links are
  T1 work; they are the cheapest place to spend tokens and the easiest to verify.
* **Measure the split, not the spend.** The number worth tracking is *fraction of signatures that
  pass the gate on the first attempt*. That number says whether the frontier prompt is good; total
  tokens says nothing about whether the artifact works.

## Failure modes recorded here so they are not rediscovered

| Failure | How it looks | Gate that catches it |
|---|---|---|
| Signature matches everything | every request tarpitted, site down | step 7 blast radius; `fp_guard` fixtures |
| Signature matches nothing | dead weight, a false sense of coverage | step 4 must produce a live match |
| Overfit to one PoC byte | next variant walks past it | step 6 bypass corpus |
| Invented request shape | passes the fixture, never sees real traffic | step 4 fires at a real binary, step 5 controls |
| Encoding a claim, not a fact | "this CVE does X" with no source | provenance rule (`source:` + archived bytes) |
| Protocol-level claim on a path-only matcher | signature cannot see the thing it claims | the renderer refuses header/body-targeting patterns on a log format that does not record them |
