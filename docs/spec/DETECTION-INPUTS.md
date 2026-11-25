# Detection Input Design: exploit signatures + Wazuh behavioural promotion

**Status:** accepted direction, v2
**Date:** 2026-11-12
**Supersedes:** v1 of this file, and the single-input detection assumption in the original design brief

**Revision note.** v1 proposed that signatures feed the controller's scoring model and only
"promoted" signatures could quarantine on one hit. The owner rejected that: the regex path is
for **PoC/exploit-specific** patterns, not generic probes like `/.env`, and an exact exploit
match should drop the source straight into the tarpit. Wazuh owns the behavioural
"innocent poke → full scan" promotion. v2 adopts that. It is simpler and more correct than v1,
for the reasons in §1.

## 1. Two classifiers with different epistemics — do not merge their outputs

| | **Path A — exploit signature** | **Path B — behavioural (Wazuh)** |
|---|---|---|
| Asserts | this source sent a known exploit payload | this source is behaving like a scanner |
| Nature | deterministic, categorical | probabilistic, correlated over a window |
| False-positive expectation | ~none, if the pattern is genuinely specific | the whole design problem |
| Latency | the request itself | seconds to minutes |
| Coverage | narrow — only traffic matching a published payload | broad — all scanning behaviour |
| Value over time | **bursts** after a disclosure | **baseline**, always on |

**Why they must not be summed.** A categorical fact and a heuristic do not add. "Exact match on
the published CVE-2026-119618 request shape" is not 5 points of suspicion; it is a fact that
changes what we know about the source. Adding it to "+2 for high request rate" produces a number
that means less than either input alone and hides which one fired.

**What the controller stops doing.** Under v1 the controller owned a re-implementation of the
brief's §9 scoring table. It should not. Scoring and promotion are Wazuh's job (or Fail2ban's).
The controller **consumes verdicts** from both paths and owns state, leases, expiry, allowlist
precedence, and map generation. That removes a duplicated classifier and the drift risk between
our copy of the scoring model and Wazuh's rules.

**The two paths still feed each other.** A Path A match is a high-value fact that Wazuh should
also see: the controller emits a structured audit log, Wazuh ingests it as a custom log source,
and Wazuh can then correlate "this IP matched three different exploit signatures in ten minutes"
— a stronger signal than either path alone. Path B promotions, in turn, tell us which IPs to
watch closely for future Path A hits.

### 1a. Implemented: the controller audit log (E13, 2026-11-14)

The contract described above - Path A tells Wazuh what it decided - is implemented as
`/var/log/adaptive-tarpit/audit.jsonl`. One compact JSON object per **address**, appended on every
state change (`claim`, `revoke`, `expire`, `bypass`), `0644 root:root`, fsynced before the command
returns.

```json
{"author":"pi","event":"claim","host":"web01.example.org","ip":"203.0.113.98","result":"added",
 "schema":1,"source":"CVE-2026-119618/probe_path","ts":"2026-11-15T01:57:39Z","ttl":86400,
 "verdict":"confirmed"}
```

Per-address rather than per-command is the part that matters: Wazuh correlates on the address, and the
question it needs to answer - "did this IP match three different exploit signatures in ten minutes" -
is only answerable if each address gets its own line carrying its own `source`. Allowlisted
suppressions are emitted too (`result":"allowlisted"`), otherwise the feed silently understates what
the controller decided and Wazuh cannot see that a monitoring probe was protected.

Ingestion needs no custom decoder:

```xml
<localfile>
  <log_format>JSON</log_format>
  <location>/var/log/adaptive-tarpit/audit.jsonl</location>
</localfile>
```

Two deliberate behaviours. A write failure is a `warning:` on stderr and exit 0, not a failed command:
the state change has already committed, and converting a successful claim into a non-zero exit because
a *log* could not be written would leave the caller unable to tell whether the claim exists. And
`--no-audit` exists for tests and dry runs, because a rehearsal that mutates the production feed is
not a rehearsal.

## 1b. Decision: no hard blocks — certainty changes the TTL, not the action

Owner's rules, accepted verbatim: *"there is no threshold if you send code looking to actively
exploit things"*, *"we want to waste their time more than anything else"*, *"that slows them down
on their way across the network and the internet"*, *"i dont want hard blocks"*.

The design does not block on a confirmed claim: *confirmed → tarpit*, because two facts make a block
the wrong answer:

1. **A block is the fastest feedback an automated tool can receive.** A RST or a 403 costs the
   attacker about a millisecond and one retry slot, then they move on. If the objective is
   consuming attacker time, a reject is close to the worst available answer — it is the second
   fastest response after a normal 200, and it hands them a clean conclusion.
2. **By the time a log-based signature match happens, the exploit request has already been
   processed by the vulnerable code.** Blocking the source afterwards protects nothing from that
   request. Patching protects, or not serving the vulnerable protocol protects. Blocking does not.
   (This also retires the "block to keep them out of the vulnerable parser" argument, which only
   ever applied to an inline reject — and an inline reject is a fast answer, which is exactly what
   we are trying to stop giving.)

**Policy:** every classified source is tarpitted. Reject exists only as **resource-budget
backpressure** (brief §13.4), never as a classification outcome. The map value becomes
`0 | 1 | 2` where `2` means "over quota — answer this one cheaply" and clears automatically when
the quota frees. It does not mean "this IP is an enemy."

**Certainty moves the TTL and the deception budget instead:**

| Verdict | Action | TTL | Rationale |
|---|---|---|---|
| Exploit payload matched (certain) | tarpit | 24 h | Safe to hold long — we know it is not a legitimate user |
| Behavioural scan promoted (probable) | tarpit | 15 / 30 / 60 m ladder | Short, to cap false-positive damage on shared NATs |
| Sub-threshold suspicion (weak) | observe | n/a | Log only |

Because we now hold confirmed adversaries for a day, **deception quality matters more, not less.**
A confirmed adversary comes back, and hits our other hosts. A scanner that learns it is being
fooled stops wasting its own time — so `B9` (per-signature response profiles) moves ahead of
generic profile work, and cross-host deception consistency becomes a real requirement (§10).

**Objective, restated from the owner's wording.** The target is the scanner's *global* sweep
throughput — hosts-per-day across the internet — not the health of one vhost. Every host that
burns ten minutes of a scanner's time reduces how many other hosts it can reach. Two
consequences: the **product is the fleet, not the PoC** (one slow host is noise; a fleet of slow
hosts is the countermeasure), and **the same fake application must be consistent across hosts**,
because an attacker that sees three different "versions" of the same app on three of our hosts has
learned more than we taught them.

**The measurement caveat that gates all of this.** A tarpit only wastes time on clients that
*wait* for responses. A fully asynchronous, pipelining scanner that never blocks on a response
loses nothing whether we answer slowly, answer fast, or refuse — so for that client class the
tarpit and a 403 are equivalent. Brief question 15 ("which clients simply timeout or abandon the
connection?") is therefore a prerequisite measurement, not a later refinement: until we know which
client classes wait, we cannot claim a time-wasted number, only a theoretical one.

## 2. Enforcement tiers, and why exactness makes Tier 1 cheap

```
Tier 0  Apache RewriteMap IP lookup        inline, one hash lookup per request
Tier 1  Apache signature match             inline, PCRE per request
Tier 2  Access-log / Wazuh ingestion       near-line, seconds
Tier 3  nftables set                       connection level
```

v1's objection to Tier 1 was per-request PCRE cost, and it was only valid for a large set of
generic probe regexes. **The owner's refinement removes most of that objection:** a small set of
*exact* exploit URIs compiles to a cheap alternation, and can be evaluated on every request for
negligible cost. A set of 5,000 fuzzy probe regexes is a different story; 20 exact exploit
patterns is not.

Revised build order: **Tier 1 (exact signatures) and Tier 2 (Wazuh ingestion) are both early**,
because Tier 1 is now cheap and is the path that quarantines on the triggering request. Tier 0
stays as the memory that makes the quarantine persist across subsequent requests.

## 3. Signature format

`controller/signatures/signatures.yaml`, versioned in git. One entry per **CVE**, carrying its
variants — not one entry per regex.

```yaml
- id: CVE-2026-119618
  cve: CVE-2026-119618
  title: Apache mod_http2 assign_headers RCE
  source: https://github.com/googlesky/CVE-2026-119618      # provenance, always
  class: exploit                    # exploit (Path A) | behaviour (Path B, Wazuh-side)
  vuln_layer: protocol              # protocol | module | app - decides mitigation vs deception
  variants:                       # a CVE is a set of payloads, never one pattern
    - match: { protocol: [h2, h2c], method: [GET, POST],
               requires_content_type_without_length: true }
      response_profile: generic_slow
    - match: { uri_regex: "^/index\\.php(/|$)" , method: [GET] }
      response_profile: slow_error
  response_profile_default: generic_slow
  verdict_to_report: vulnerable     # vulnerable | absent — see §4
  applies_to: [all]                 # or explicit vhosts
  fp_guard: []                      # local real paths that suppress this signature
  ttl: 86400                        # see §6; exploit matches outlive behavioural ones
  added: 2026-11-12
  review_by: 2027-05-12             # signatures expire; they must not accumulate forever
  evidence_max_bytes: 512           # bounded, sanitised capture
```

Field rationale:

- **`variants`** — real exploit traffic varies (path prefixes, `index.php` forms, casing, URL
  encoding, extra headers). Nuclei templates carry multiple matches per CVE for exactly this
  reason. One regex per CVE gives you exactness *and* near-zero coverage of the variants.
- **`class`** — makes Path A vs Path B explicit in the data, not inferred.
- **`response_profile`** — per variant, see §4.
- **`fp_guard`** — if a matched path is real on that vhost, suppress rather than quarantine.
- **`review_by`** — retirement is mandatory; an unbounded signature set eventually harms
  legitimate traffic.
- **`evidence_max_bytes`** — bounded, sanitised capture; no unbounded attacker strings in logs.
- **`vuln_layer`** — decides whether a match is a **mitigation** or only a **deception**. See §3a.
  A signature without it cannot answer the only question that matters on a vulnerable host:
  "did we just stop this, or did we only slow them down?"
- **`posture`** (optional, per variant) — the server configuration the variant is valid under.
  `h2c_preface_on_http1_only` only means anything once `Protocols` excludes `h2c`; enabling it on
  an h2-enabled vhost is a silent no-op, which the harness refuses.
- **`verify`** (optional, per variant) — the measurement that turns an expected behaviour into an
  observed one. Regexes derived from a PoC are hypotheses until a fixture proves them.
- **`test_strings`** (per variant, as `positive`/`negative`, `log_positive`/`log_negative`,
  `header_positive`/`header_negative`) — every pattern ships with the strings that must match it
  and the strings that must not. `tests/unit/test_signatures.py` enforces both. A pattern with no
  negative fixture is how a signature ends up matching legitimate traffic in production.

## 3a. Which layer the vulnerability lives in decides what a rewrite rule can do

The question the brief never asks, and that has to be answered per signature: **if we match this
request in Apache, have we stopped the vulnerability, or only delayed answering it?**

Apache reads the request line and request headers into the `request_rec` **before** any module
hook runs; `mod_rewrite` acts in the `map_to_storage` phase, downstream of parsing. A rewrite rule
can therefore only ever act on a request Apache has already finished parsing. That gives three
cases:

| `vuln_layer` | Where the vulnerable code executes | Can a rewrite match prevent it? | What the tarpit is |
|---|---|---|---|
| **protocol** — httpd core, `mod_http2`, `mod_ssl`, the request-line parser | request creation / parsing, upstream of every hook | **No.** The bug runs before the rule is consulted. | deception + attempt-rate reduction only |
| **module** — `mod_php`, `mod_cgid`, `mod_dav`, `mod_proxy` | handler phase, downstream of the hooks | **Yes.** Refuse the URI and the module never runs. | mitigation **and** deception |
| **app** — the framework/CMS behind the web server (the Wordfence case) | handler phase, often a different process | **Yes.** The classic virtual-patch case. | mitigation **and** deception |

**Applied to CVE-2026-119618.** `assign_headers()` runs while `mod_http2` converts the HEADERS
frame into the `request_rec` - inside request creation. A rewrite rule cannot fire before the
corruption happens, so on a vulnerable vhost an inline match buys deception and a lower attempt
rate, **not** protection. The only true mitigations are patching to 2.4.71 or removing `h2`/`h2c`
from `Protocols`.

**The one exception, and it is why the HTTP/1.1 downgrade and the tarpit are complementary rather
than alternatives.** Once `Protocols` excludes `h2c`, `mod_http2` no longer claims cleartext
connections, so an h2c client's RFC 7540 connection preface (`PRI * HTTP/2.0`) is parsed by the
HTTP/1.1 request-line reader and logged as method `PRI`. The attempt becomes both harmless and
trivially matchable - the single case where matching this CVE in mod_rewrite genuinely stops it,
because the vulnerable parser never touches the connection. **The downgrade is the mitigation, the
tarpit is the response, and the downgrade hands the tarpit a free, high-fidelity signature.**

## 4. Response pairing — the part that decides whether the deception works

This is the gap the v1/v2 discussion missed and it matters more than the regex syntax.

If we match an **exact exploit request** and answer with the **generic slow `.env` tarpit**, we
break the deception. The PoC expects a specific response — often a specific marker string that
tells the tool the vulnerability is present. A Java exploit answered with a slow-drip `.env` file
teaches the attacker something is wrong far faster than a fast 404 would.

So **each signature variant carries the response it should produce**, and the tarpit answers that
specific request plausibly and slowly, rather than generically and slowly.

The second decision per signature is `verdict_to_report`:

- **`vulnerable`** — the honeypot answer. The scanner records a finding, often retries or attempts
  follow-on exploitation, and spends more time. Maximum time cost to the scanner.
- **`absent`** — plausible "not installed / patched" answer, delivered slowly. Lower reward,
  lower risk of the attacker concluding the host is inconsistent.

Default to `vulnerable` for Path A: the whole point is to convert a 200 ms answer into a
multi-second interaction the scanner then wants to verify.

**Generalised rule for the project:** the tarpit's value from exact signatures comes from
*answering the exploit correctly*, not from being generically slow. Slow-and-correct makes a
scanner log a finding and burn time verifying it. Slow-and-wrong makes it learn it is being
fooled — and a scanner that learns stops wasting its own time.

## 5. Coverage limits of exactness — say it plainly

Path A fires only when someone sends a payload we already have a signature for. Opportunistic
scanning is dominated by generic probes; exploit-specific traffic is a minority of it. So:

- **Path A is a burst capability.** Its value spikes in the days-to-weeks after a disclosure —
  which is exactly the "lapse in patch coverage" scenario the owner described, and exactly when
  the package fix is often still unavailable (as with Oracle EL9 today).
- **Path B is the baseline capability.** Always on, catches the boring majority.

They are not redundant and their relative value changes over time. Building Path A alone would
give us a system that does almost nothing most weeks and a lot during a disclosure window — which
is a legitimate design, provided we are honest about it rather than describing it as general
scanner defence.

## 6. State and TTL asymmetry

The brief's §10 state machine splits `TARPITTED` into two states, because the two paths produce
different confidence and should not share a penalty policy:

```
NORMAL → OBSERVED → TARPITTED_SUSPECT   (Wazuh/Fail2ban promoted)
       → TARPITTED_CONFIRMED (exploit signature matched)
       → BLOCKED → EXPIRED, with ALLOWLISTED overriding everything
```

- **`TARPITTED_SUSPECT`** keeps the brief's escalation ladder: 15 m → 30 m → 60 m.
- **`TARPITTED_CONFIRMED`** should outlive it — a source that sent a known exploit payload is a
  known adversary, not a maybe. Default 24 h, configurable, always expiring. An address that probes for a CVE the target has already patched is still worth
  remembering: it proves the host was enumerated.
- **Allowlist still wins on both paths.** An authorised vulnerability scanner legitimately
  sends exploit payloads; without allowlist precedence, our own scanner would quarantine itself
  into the tarpit and then report the site as broken.

## 7. What the access log can and cannot show

A hard constraint on Path A, and it is not in the brief.

The Apache access log gives us: client IP, timestamp, method, path, query string, protocol,
status, bytes, Referer, User-Agent. **It does not contain the request body.**

Consequences:

- Signatures whose evidence is in the path, query string, method, headers, or protocol are
  matchable from the log (Tier 2) and from an inline Apache rule (Tier 1).
- Signatures whose evidence is in the **POST body** — which is most RCE PoCs, including
  CVE-2026-119618's header-table shape only partially — are **not** detectable from the access
  log. Detecting those requires a body-capable engine: ModSecurity, the tarpit itself, or the
  gateway's `body_markers` (2026-11-24: it already buffers the body up to `max_body_bytes`, and a
  literal marker check over those bytes stopped PHP2Shell chain A with the counterfactual measured).
- Therefore the signature schema's `match` block must declare which field it targets, and the
  tooling must refuse to enable a body-targeting signature on a host without a body-capable
  engine. Silent no-ops are worse than refusals.

## 8. Safety gates before a signature may enforce

1. **Replay** — `adaptive-tarpit sigtest --against /var/log/httpd/access_log-2026*` reports
   matching paths, distinct source IPs, the would-be-quarantined list, and any signature matching
   a path that actually exists on the vhost. This is the "prove it in test" rule applied per
   signature.
2. **Observe-only period** — log matches, take no action, review the candidate list.
3. **Explicit promotion** to enforce, with a `review_by` date.
4. **Reversibility** — removing a signature restores normal routing without an Apache restart and
   must not orphan leases created by another detector.
5. **ReDoS guard in CI** — reject nested unbounded quantifiers, assert a compile-time ceiling. A
   pathological regex in a hot path is a self-inflicted outage.
6. **Body-capability check** — refuse to enable a body-targeting signature without a
   body-capable engine (§7). The gateway is one, via `[detection] body_markers`; a log-only
   host is not.

## 9. One writer, many claimants

The controller is the only writer of state. Path A (signature matcher), Path B (Wazuh Active
Response), and the Fail2ban action each submit **claims** carrying `source`, `class`, `ttl`,
`rule_id`, and `evidence`; the controller merges them into leases. No claim may delete another
detector's lease — the rule the brief already states for Wazuh/Fail2ban in §7.3 extends to the
signature path unchanged. A Path A claim additionally upgrades state to `TARPITTED_CONFIRMED`.

