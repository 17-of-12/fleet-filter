## What this changes

<!-- One or two sentences. The diff says what; this says why. -->

## Why

<!-- The problem, the measurement, or the CVE. If a rule changes, name the exploit it targets. -->

## Evidence

<!-- For a detection change: the exploit working without the control, the same request through it,
     and a benign request that still works. For a code change: the test that fails before and passes
     after. "Tests pass" is not evidence; the test that would have caught this is. -->

## Checks

- [ ] `bin/check.sh --all` passes locally
- [ ] A detection change has positive *and* negative fixtures
- [ ] A ledger entry added or changed has evidence the exporter can publish
- [ ] Docs updated where the behaviour a user sees has changed
- [ ] Commits are squashed to one logical change
