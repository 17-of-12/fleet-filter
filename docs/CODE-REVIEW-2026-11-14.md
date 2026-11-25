# Fleet-Filter — independent source-code review

**Snapshot:** `Fleet-Filter-20261114T120542Z.tar`, repository HEAD as exported: `c8078f9` (2026-11-13).  
**Review date:** 2026-11-14. **Method:** source inspection of every implementation/config/test file, isolated controller CLI probes, direct responder `_resolve()` probes, a local HTTP keep-alive test, two project test harnesses, and Wazuh protocol/rules documentation comparison. **No fleet host was contacted, and no remote service was modified.**

## Executive assessment

The proof-of-concept successfully demonstrates a useful architectural mechanism: Apache can divert mapped clients to a slow-drip localhost responder while unmapped clients continue to the normal vhost. The repository documents 13 ms versus 5,271 ms measurements on the test host and describes port-80/443 enforcement. This evidence is **from repository documentation**, not independently repeated against lab-web01 during this review.

**Recommendation:** keep it canary-only. Do **not** roll out to production/fleet until P0 findings are fixed and an Apache/resource stress matrix is passed. Its architectural principles are good; the current controller and responder do not yet uphold its own fail-safe, confidentiality and resource-budget invariants.

## Findings

### PT-01 — P0 — Last lease expiration leaves an active Apache map entry

**Locations:** `controller/adaptive-tarpit.py:422–428`, `:440–449`, `systemd/adaptive-tarpit.service:6–8`, `systemd/adaptive-tarpit.timer:5–10`.

`expire --render` purges the last row, then `do_render` rejects an empty replacement because the previous map has entries. No `--allow-empty` switch is provided on the `expire` parser. The SQLite row is gone, but Apache still sees `IP 1`, and future expirations repeat the failure. A 15-minute suspect can remain diverted indefinitely. **Reproduced** with a 1-second lease.

**Required change:** Distinguish *successfully queried empty state* from *state-read/replication failure*. Render empty on valid authoritative zero-lease state, retaining a separate stale-on-error fallback when state cannot be read. Add a test for last-lease expiration (including a reboot/restart and removal of an allowlisted last lease).

### PT-02 — P0 — Wazuh Active Response protocol mismatch; potential stdin hang

**Locations:** `detector/wazuh/active-response/fleet-filter.sh:18–36`, `controller/adaptive-tarpit.py:164–220`, `tests/unit/test_ingest.py:225–245`.

The adapter treats its stdin as a raw alert. Wazuh 4.x AR sends `{version, origin, command, parameters: {alert, ...}}`; the actual alert is `parameters.alert`. Passing a documented `command=add` envelope directly to `ingest` yielded `error: no source address in alert (rule id ?)`. The adapter uses `payload=$(cat)` to wait for EOF, whereas Wazuh's wire protocol sends newline-delimited messages on a pipe that may remain open. For a stateful AR, `command=delete` must be recognized/ignored or handled according to explicit lease policy; it must never turn into a new claim.

**Required change:** Parse **one line** from stdin, validate schema and command, extract `parameters.alert` on 4.x, and normalize to internal claim. Bind the format to the installed Wazuh manager version (repo notes agent is 4.14.10, manager version unknown). If using stateful responses, implement the required `check_keys` exchange; otherwise configure and test truly stateless AR. Use captured manager payloads as fixtures. Sources: [Wazuh AR docs](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html), [Wazuh 4.x→5.x migration](https://github.com/wazuh/wazuh/blob/main/docs/guide/migration/active-response.md).

### PT-03 — P0 — Tarpit exposes live application source and files outside docroot

**Locations:** `tarpit/server/server.py:64–65`, `:86–108`, `systemd/tarpit-test.service:12–20`.

For any requested regular file, the responder reads bytes directly from the live DocumentRoot and replies `200`, bypassing Apache's handlers, rewrite rules, authorization and `.htaccess`. Thus a `.php` application source that Apache normally executes can be returned as literal PHP source. `os.path.isfile` follows symlinks: `docroot/link → outside_directory` was read successfully in a local test. `candidate.startswith(docroot)` is also insufficient for sibling directories with identical prefixes (e.g. `/tmp/www-backup` passes `/tmp/www` prefix check), and a noncanonical path was observed to return that sibling's file when received directly by the backend. SELinux/Unix permissions may reduce exposure on the current host, but do not provide a safe design boundary. **Reproduced** both raw PHP file disclosure and symlink escape with dummy local files.

**Required change:** Decouple the deception responder completely from production files. Serve fixed, reviewed response profiles and bounded sanitized snapshots (and never secrets), not live DocumentRoot reads. If any file-like backend remains, use canonical `realpath`/`commonpath`, reject symlinks, enforce an explicit public-file allowlist, and treat Apache authorization as separate from filesystem readability. Add php-source, symlink and sibling-prefix regression tests.

### PT-04 — P0 — Quota value `2` does not provide resource backpressure

**Locations:** `controller/adaptive-tarpit.py:305–327`, `apache/tarpit-test.conf:20–26`, `apache/lab-web01.ssl.conf:5–12`, `controller/adaptive-tarpit.py:500–525`.

`render --max-tarpit 1` produces one `IP 1` and one `IP 2`, **reproduced**. Both Apache vhosts match `${map:REMOTE_ADDR} ^[12]$` and proxy both values to the same backend. This is explicitly contrary to the project rule that `2` means **over-quota**, a cheap fail-closed response/reject under defender-resource pressure. Moreover `max_tarpit` defaults to zero/unlimited on ingest and render, while the scheduled expiry command has no such option: even a manually capped map can be uncapped by the next render. Finally, the present quota counts **leased IP rows**, not live response concurrency or Apache busy workers, so it is not a resource budget.

**Required change:** Make `2` a distinct routing action that never hits the real site and never allocates a costly tarpit stream; enforce caps on concurrent backend responses, per-IP responses, fds, bytes, Apache busy workers and request duration. Derive `2` from measured live capacity rather than an arbitrarily sorted set of lease rows. Preserve the cap across all render paths. Load-test the cap and the restoration to `1` as capacity becomes available.

### PT-05 — P1 — Stronger evidence does not promote an existing suspect

**Locations:** `controller/adaptive-tarpit.py:114–135`, `:243–284`.

`ingest` skips an IP already leased, regardless of source/rule/verdict; direct `Store.claim` with `confirmed` extends expiry but updates neither `verdict` nor `source`/`author`. **Reproduced**: suspect → ingest confirmed = skipped; suspect → direct confirmed = 24-hour expiry, recorded verdict still suspect. A single IP primary key also cannot correctly represent independent claims from Wazuh, Fail2ban, explicit signatures, or other hosts. This conflicts with `docs/FLEET-STATE.md`'s composite `subject_ip, authoring_host` design.

**Required change:** Store claim rows keyed by IP plus stable claim identity/source/host, each with own expiry/evidence; derive effective verdict from all unexpired claims. At minimum implement monotonic `suspect`→`confirmed` promotion, never downgrade an active confirmed claim from weaker evidence, and prevent removal of one claim from discarding another.

### PT-06 — P1 — HTTP request bodies remain unread on persistent backend connections

**Locations:** `tarpit/server/server.py:132–162`.

`do_POST` immediately calls `_serve` without consuming `Content-Length` or decoding/discarding chunked bodies. HTTP/1.1 keep-alive then treats the leftover body as the next request line. **Reproduced** locally: POST with four bytes of body followed by GET returned a 403 and then `501 Unsupported method ('ABCDGET')` rather than parsing the real second request. This creates proxy/backend request desynchronization and unreliable behavior under normal POST/keep-alive traffic.

**Required change:** Either boundedly consume/discard bodies with timeouts and explicit transfer-framing validation, or always close the backend connection after such a request (`Connection: close` plus `self.close_connection = True`). Test POST with valid body, chunked body, pipelining, and malformed lengths through Apache as well as directly.

### PT-07 — P1 — Responder resource costs are unbounded

**Locations:** `tarpit/server/server.py:54–70`, `:86–126`, `:194–207`.

`ThreadingHTTPServer` allocates one thread per live connection with no global/per-IP semaphore, no explicit idle timeout, no maximum request size and no maximum response bytes. `_resolve` reads a whole file into memory; `_drip` creates a list of all small chunks, then writes/flushes/sleeps for **every** chunk. Five seconds is not a memory, fd or worker cap. A 3,539-byte body with 3-byte chunks implies roughly 1,180 write/flush iterations per request. The actual Apache worker economics have not been demonstrated under load.

**Required change:** Set bounded connection pools, global/per-IP concurrency limits, header/body/idle/total timeouts, maximum response size and file/snapshot sizes, streaming without full chunk-list materialization, and explicit overload response. Quantify attacker time consumed per defender worker-second (and impact to normal p95 latency), not just response duration.

### PT-08 — P1 — Draft Wazuh rules have syntactic and semantic problems

**Locations:** `detector/wazuh/rules/fleet-filter.xml:16–82`.

All six rules place `if_group` on the `<rule ...>` **attribute**, while the documented Wazuh rules language uses an **`<if_group>...</if_group>` child element**. XML well-formedness does not prove manager loadability. Separately, rule `120006` is described as a *confirmed exploit signature* but only checks group `fleet-filter` plus the presence of a source IP. Once translated into a valid parent-group condition, that predicate could classify ordinary behavioural events as confirmed. The file's header correctly marks this rule set as **DRAFT, not installed**.

**Required change:** Move conditions into legal Wazuh child elements and validate with the exact target Wazuh manager using `wazuh-logtest` and manager config-check. Define a distinct signed/structured controller audit event and match its exact decoder/type/signature fields; never infer exploit certainty from generic group membership. Verify real decoded field names for `120002`/`120006`. Sources: [Wazuh rules syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html).

### PT-09 — P1 — Arbitrary high-severity Wazuh alerts become 24-hour confirmed exploit verdicts

**Locations:** `controller/adaptive-tarpit.py:271–282`, `tests/unit/test_ingest.py` test 3.

`level >= 12` is equated to `confirmed`. The project's own distinction says only exact exploit evidence is categorically confirmed, while behavioural/correlation sources are suspect. A high-level authentication alert need not prove exploitation. The tests intentionally reward this level-based promotion, so merely passing them does not validate the semantic policy.

**Required change:** Map only a narrow allowlist of independently validated signature rule IDs or explicit trusted verdict fields to `confirmed`. Every other accepted event is `suspect`, irrespective of generic Wazuh severity, unless a specific rule contract says otherwise.

### PT-10 — P1 — Original client identity lost at the backend

**Locations:** `tarpit/server/server.py:163–173`, `apache/tarpit-test.conf:26–29`, `apache/lab-web01.ssl.conf:12–13`.

The responder logs `self.client_address`, which under an Apache loopback proxy is Apache's local `127.0.0.1` rather than the quarantined scanner. This makes logs/telemetry misleading and prevents safe per-source quotas in the backend. The backend also ignores the preserved Host when choosing a response profile. It should not naively trust incoming `X-Forwarded-For`, which may contain attacker-controlled values.

**Required change:** Have Apache sanitize/replace inbound forwarded identity, then convey a trusted original-client IP to a loopback-only backend, with a strict authenticated/trusted-hop boundary. Test the identity path when the scanner sends forged forwarding headers, and apply per-IP limits at the correct trust boundary. Implement stable cross-host response profiles.

### PT-11 — P1 — Incomplete map-loss/fail-closed design

**Locations:** `controller/adaptive-tarpit.py:431–453`, Apache RewriteMap vhost rules, `systemd/adaptive-tarpit.timer`.

The system treats the map as a generated artifact but no continuous reconciliation detects its deletion, corruption or temporary absence before the next periodic task. If a required lookup fails or has no entry, the regex does not match and the request normally continues to the real vhost. A *backend outage with a valid map* is different and should typically yield proxy error rather than production fallthrough. Test the distinct scenarios; do not claim one property for both.

**Required change:** Startup/preflight, map canary/health checks, atomic restoration, and a routing-level fail-closed condition for known quarantined sources even when the map/backend path fails. Document recovery behavior and measure it on both real vhosts.

### PT-12 — P2 — Explicit fingerprint disclosed in every tarpit response

**Locations:** `tarpit/server/server.py:69–70`, `:145`, `docs/FLEET-STATE.md` deployment notes.

`X-Tarpit: test` is emitted by the PoC and logged as present in the real canary. This deliberately distinguishes the deceptive response from the real vhost. Fine for a PoC; remove before any adversary-facing rollout. Review other headers and status/length/ordering for fidelity as well.

### PT-13 — P2 — Path A signature store is not yet an executing detector

**Locations:** `controller/signatures/signatures.yaml`, `tests/unit/test_signatures.py`, `TODO.md` E9–E13.

The signature YAML and its fixture harness validate expressions, but no production tailer, inline-rule generator or ModSecurity rule compiler consumes the YAML. The current enabled vhosts only have IP map lookups. Thus specific CVE signature data cannot autonomously classify a first request in this snapshot; behavioural fail2ban is the actually deployed input. **This is tracked planned work, not a regression.** Make the first non-capricious exploit-path end-to-end test a rollout gate.

### PT-14 — Operational blocker already acknowledged: Wazuh firewall-drop conflicts with the product

**Location:** `docs/WAZUH-ASK.md` and `TODO.md` unresolved issues.

The archive records Wazuh rule 931151 invoking `firewall-drop` on the canary. That blocks requests before any tarpit can run. Owner decision and manager change are pending; do not mark this resolved merely because fail2ban works. This is **already known and documented** by the project.

## What is working well

- Clear separation between classification and enforcement and strong stated resource economics goal.
- Atomic `os.replace` map writes and idempotent no-op when map state is unchanged.
- `REMOTE_ADDR` map lookup avoids trusting client-provided forwarding headers at the Apache routing point.
- Local allowlist precedence on new claims.
- Defensive refusal to overwrite a populated map with a completely empty one, though its current implementation mistakes legitimate expiry for corruption.
- Documentation records measured PoC response times, protocol-specific observations and blockers rather than claiming production readiness.
- Python stdlib canary responder was an effective way to prove Apache proxy routing without immediately deploying Node/upstream.

## Test evidence

The snapshot's existing **`tests/unit/test_ingest.py` passed 52/52 checks** and **`tests/unit/test_signatures.py` passed 29/29 checks** after restoring execute permissions on the extracted AR shell script (the tarball itself correctly marks it executable). This is 81 passed assertions, not 81 independent end-to-end scenarios. The tests do not cover actual Wazuh envelopes, final-lease expiry, promotion, backend confidentiality, keep-alive body framing, quota enforcement or resource exhaustion. No current tests are present in `tests/integration/`, `tests/load/` or `tests/security/`.

**Independent reproduction summary:**

| Test | Result |
|---|---|
| `claim IP --ttl 1 --render` then `expire --render` | Database empty; stale `IP 1` remains; exit 1 |
| `render --max-tarpit 1` with 2 leases | `IP 1` plus `IP 2`; both still match Apache `^[12]$` proxy rule |
| Ingest documented Wazuh 4.x `parameters.alert` envelope | Exit 1, no source address |
| Ingest confirmed for already-leased suspect | Skipped; remains suspect |
| Directly claim confirmed for suspect | Expiry extended; stored `verdict` stays suspect |
| Request raw `private.php` from responder | Raw PHP source returned with HTTP 200 |
| Request symlink to out-of-docroot file | External file returned with HTTP 200 |
| Request noncanonical path into sibling whose name has docroot prefix | Sibling file returned with HTTP 200 |
| POST with unread four-byte body then keep-alive GET | First response 403; second response 501 to invented method `ABCDGET` |

## Recommended implementation order

1. **Before any more live testing:** PT-03 confidentiality leak, PT-01 expiration bug, PT-02 Wazuh envelope/transport bug. Keep the test vhost isolated from sensitive content while fixing.
2. **Make the state machine honest:** PT-05 separate claims/promotion; PT-09 source-level certainty; exact allowlist and expiry/revoke tests.
3. **Make defender economics real:** PT-04 distinct over-quota action, PT-07 enforced response limits, PT-06 request framing and timeouts, PT-10 trustworthy client identity.
4. **End-to-end integrations:** PT-08 validate draft rules on manager; PT-13 connect the signature store to an actual detector; PT-11 prove no production fallthrough in multiple failure modes; resolve PT-14 with the Wazuh admin.
5. **Rollout gates:** 24h canary soak with normal traffic and bounded hostile test traffic; all `GET/HEAD/POST`, chunked, keep-alive, TLS/HTTP2 (where enabled), map missing/corrupt, backend down/restarting, stop/start, OOM, quota rise/recovery, mass simultaneous expiry, multi-vhost routing, and source-IP spoof attempts. Measure busy workers, fd count, resident memory, normal p95/p99 latency, 5xx error rate, active stalled responses and scanner time cost.

## Product strategy

Preserve the stated north star: waste *scanner fleet time per unit of defender cost*, not connection count at any price. The current per-connection Python-thread approach is fine for an isolated proof of concept, but probably not an efficient production data plane. After correctness, benchmark a bounded async/nonblocking backend and a cheap quota-overflow response against the existing threaded proxy design. Do not presume a Node, Python, Apache module or nftables path wins without measuring the Apache TLS/worker costs and the scanner's behavior.

## Hand-off success criteria

All of the following should be demonstrably true after changes:

- An expired **last** lease disappears from the actual Apache routing map without manual flags.
- Any Wazuh AR `add` event is accepted in the installed version's protocol and `delete` never creates a new lease; no stdin hang.
- Independently sourced claims coexist; a confirmed exploit promotes a suspect and survives weaker claim removal.
- A mapped source **never** reaches a production secret or real dynamic source file through the tarpit.
- Over-quota means **cheap reject/failure**, not another expensive tarpit thread, and it automatically clears with capacity.
- Malformed/oversize bodies and idle connections are bounded and cannot desynchronize subsequent backend requests.
- Apache validates routing on **every** intended vhost; map/backend failures have tested, explicit behavior.
- The Wazuh draft passes the real manager's validation and log-test tooling before being enabled.
- Under the target concurrency test, the tarpit demonstrably consumes more attacker work than defender work without degrading non-scanner traffic.
