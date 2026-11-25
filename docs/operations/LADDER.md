# The escalation ladder

Answers one question: **how long should an address stay tarpitted, given how often it has been
caught?** The spec gave the rungs (`15m -> 30m -> 60m -> drop`) and required machine-readable
transition reasons. Both live in `controller/ladder.py`; `cmd_claim` consults it and writes the
result into the E13 audit line.

## The ambiguity, and the decision

The spec does not say what `drop` means, and the two readings conflict:

| Reading | Meaning | Conflict |
|---|---|---|
| **release** | the quarantines end and the address returns to normal service | consistent with the owner's "no hard blocks" rule (H7: a persistent reject is a defect, not a policy) |
| **hardblock** | the firewall sense of "drop" - hold the address indefinitely | exactly the hard block the owner ruled out as a default |

Neither reading is implemented as *the* answer. The rung sequence is the policy; the terminal
behaviour is a flag, so the owner's choice is a configuration change rather than a code change:

```
claim --ladder-terminal cap | release | hardblock     # default: cap
```

`cap` is the default: the address stops escalating at 60m. It satisfies the spec's ceiling (nothing
grows past 60m) without releasing a repeat offender and without introducing a hard block by
implication. Change it when the owner rules otherwise; the tests already cover all three.

## The rungs

| Prior claims | Rung | TTL | `reason_code` |
|---|---|---|---|
| 0 | `15m` | 900 | `first_observation` |
| 1 | `30m` | 1800 | `repeat_observation` |
| 2 | `60m` | 3600 | `repeat_observation` |
| 3+ | terminal | `cap` 3600 / `release` 0 / `hardblock` 86400 | `ladder_exhausted_cap` / `ladder_exhausted_release` / `ladder_exhausted_hardblock` |

**Only `suspect` verdicts walk the ladder.** A `confirmed` verdict is a fact rather than a suspicion
and takes its own 24h lease directly (`reason_code: confirmed_lease`); escalating a confirmed address
through suspect rungs would shorten a lease that evidence already justified. This matches the note
already in the controller at `DEFAULT_CONFIRM_RULES`, which says a protocol observation "gets the 15m
suspect ladder, not a 24h lease".

**An explicit `--ttl` bypasses the ladder entirely** and records no rung: the ladder did not make that
decision, so it should not claim credit for it.

## Where the history lives, and why it is not derived from `claims`

`Store.claims` rows are deleted when leases expire. If the ladder counted active claims, every
address would look new again the moment its lease lapsed and the ladder could never escalate past its
first rung. So the store gained a second table that is never purged:

```sql
CREATE TABLE IF NOT EXISTS ladder (
    ip TEXT PRIMARY KEY, claims INTEGER NOT NULL, last_claim_at INTEGER NOT NULL, rung TEXT NOT NULL
)
```

`Store.ladder_state(ip)` reads it and `Store.record_ladder(ip, rung)` increments it. The write uses
UPDATE-then-INSERT rather than `INSERT ... ON CONFLICT`, because the latter needs SQLite 3.24 and the
oldest managed host still runs its distro's stock interpreter.

## What the audit line looks like

```json
{"actor":"agent","event":"claim","ip":"203.0.113.44","ladder_reason":"repeat_observation",
 "ladder_rung":"30m","prior_claims":1,"result":"added","schema":1,"source":"s2","ts":"...","ttl":1800,
 "verdict":"suspect"}
```

`ladder_rung`, `ladder_reason` and `prior_claims` are present whenever the ladder decided, absent when
the operator overrode it with `--ttl`. That is what makes a lease length auditable after the fact
instead of inferred from a number.

## Scope note

`cmd_claim` is the path that matters operationally: it is what fail2ban's `f2b-fleet-filter` action
invokes, and it is the path any operator tooling exercises. The Wazuh
active-response ingest path (`cmd_ingest`) still claims with the flat default TTL; Wazuh active
response is not selected by default in the shipped configuration (the manager maps to `firewall-drop`), so wiring the
ladder there is scheduled with the Wazuh cutover rather than being asserted now.

## Verification

`tests/unit/test_ladder.py` - **24 checks, passing on Python 3.9 and 3.12** - covers the pure function
(all rungs, all three terminal modes, confirmed verdicts, and the three invalid-input cases) and the
store end to end (four claims from four sources auditing `900, 1800, 3600, 3600` with rungs
`15m, 30m, 60m, 60m`; `terminal=release` deleting the claims on the fourth; an explicit `--ttl`
recording no rung). `./bin/check.sh --python` passes.
