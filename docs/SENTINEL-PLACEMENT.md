# Where the sentinel runs: per host, with a central reader that cannot decide

Status: decision, 2026-11-24. Scope: the per-line scoring stage from
`docs/SENTINEL-AND-RAG.md`. Does not change the gateway's in-line path.

## The question is two questions

"Per host or central" is asked as one decision and is actually two, and separating them removes most
of the argument:

1. **Where does a line get scored?** This decides what happens when a box is unreachable, what the
   blast radius of a compromised component is, and whether containment needs the network.
2. **Where does the evidence end up?** This decides whether you can see a distributed attack, track a
   trend over weeks, and answer "has this source hit us before" - none of which is needed to contain
   one source right now.

They have different answers. Scoring: **per host, always**. Evidence: **aggregated centrally, on a pull
that cannot affect the host**.

## Why scoring is per host

* **The log is already there.** Central scoring means shipping every access line off the box - a new
  daemon, a new credential, a new failure mode - to compute a number the local CPU can compute in
  microseconds. `bin/lab-capture.py` and `detector/sentinel/features.py` read a file that exists.
* **Containment must not depend on a remote call.** The controller spool is a local directory
  (`gateway/src/spool.rs`), the map is a local file, Apache's RewriteMap reads it locally. A per-host
  sentinel emits into that same spool with `source=<model-id>`, `author=<host>` and nothing new is
  needed. If the central box is down, a host still detects, still claims, still tarpits.
* **Failure is contained.** A sentinel that crashes on host A does not blind host B. A central scorer
  that crashes blinds every host at once, and does it silently.
* **Bursts are absorbed locally.** A scan against one vhost produces a spike in one log. Scoring it
  locally spends the idle vCPU of the box being attacked instead of queueing on a shared box that is
  also serving nine other hosts.
* **Physical boxes exist.** The stated lean is right: a host with no collector, no orchestrator and no
  central infrastructure still gets detection if the sentinel ships as a unit and a binary. A design
  that only works in a VM fleet is a design that abandons the hosts you cannot rebuild on a whim.

## What central is for, and how it must be wired

Central is where **correlation** lives, because the one thing a per-host view cannot see is a
distributed scan that stays under every host's individual threshold:

* same source scoring `suspect` on four hosts within ten minutes - invisible to each, obvious together;
* a template that appears on one host and then on nine others (a worm, not a scanner);
* trend and RAG over weeks: which templates are new, which signatures never fire, which model scores
  drifted.

That is a **reader**, not a decider. It ingests events (scored templates, counts, claims), not raw
lines, and it is fed by a **pull** - the central box pulls the event spool on its own schedule:

* a host's runtime path never calls central, so central cannot slow or stop a host;
* a compromised central box can read events and cannot suppress a host's local decision;
* the pull is idempotent (spool files are immutable, `observed_at`-named), so a missed pull is a
  backlog, not a gap.

Cross-host bans are the one thing central may push back down, and they must arrive as a **claim**
(`drain-spool`) with a normal TTL and a normal expiry - not as a direct map edit - so the ladder and
the audit trail stay the only path to a verdict.

## VM versus physical does not change the split

The tempting argument is "we have a big CPU and many vCPUs, so centralize the model". That optimises
the resource that is cheap (CPU cycles) and spends the one that is expensive (independence). A
per-host ONNX classifier at tens of microseconds per line is a rounding error on any vCPU, and it
scales with the number of hosts for free because each host pays for its own traffic. Add vCPUs where
they buy something: the central correlation and RAG job, which is the only part that gets harder as
hosts are added.

## The number that matters is not placement

Measured against the current deployment, containment latency is dominated by the pipeline, not by
where the model sits:

| Stage | Today | Effect on a 1000 req/s attack |
|---|---|---|
| detection (sentinel tick) | seconds | 1k-10k requests |
| spool drain | **up to 300 s** (`adaptive-tarpit.timer`, `OnUnitActiveSec=5min`) | **up to 300k requests** |
| map render | instant | - |
| map cache (Apache `txt:` map / gateway `map_ttl`) | **60 s** | 60k requests |

So a per-host sentinel that scores in microseconds still waits up to six minutes for its claim to
become a tarpit. Moving the model to a central box would change the first row by milliseconds and
leave the other two untouched. **Fix the cadence before arguing placement**: the drain is a directory
walk and a small SQLite write, so a 5-15 s timer is affordable, and the 60 s map cache is the floor
for the log-driven path - which is exactly why the gateway's in-line path (no map lookaside) is the
one that contains a first hit in milliseconds.

Implication for the sentinel's role: it is a **reputation** source, not the primary blocker. The
gateway's signature match stops the request in front of it; the sentinel's job is to notice the source
that no signature matched and put it on the map before the next victim sees it.

## Decision

1. Sentinel runs **per host**, as its own unit, single-threaded ONNX (`intra_op_num_threads=1`,
   batched), reading the local access log and writing claims into the local controller spool.
2. It ships as a signed artifact bundle: model sha256, `FEATURE_VERSION`, threshold, training-data
   manifest. A mismatch is a refusal at load, not a best guess.
3. Central exists for correlation, trend and RAG only: **pull-fed**, event-level, never in the
   containment path, and any cross-host action arrives as a normal claim with a normal TTL.
4. Cadence work is a prerequisite, not a follow-up: 5 min drain -> 5-15 s, and state the 60 s map
   cache as the known floor of the log-driven path.
