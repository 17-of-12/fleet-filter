# Development Handoff: Fleet-Filter Security Gateway

## Mission

Design and implement a new **protocol-aware, vulnerability-aware security gateway** as an expansion of the existing Fleet-Filter project.

This gateway will operate in front of Apache HTTP Server and other potential HTTP backends, inspecting incoming requests before forwarding them to the real web server.

The fundamental objective is:

**Protect an existing web server from known vulnerability exploitation, including zero-day vulnerabilities for which vendor patches are not yet available, without unnecessarily sacrificing modern HTTP functionality or rewriting the applications being protected.**

The gateway must integrate with the existing Fleet-Filter classification, quarantine, deception, Wazuh, and Fail2ban infrastructure.

This is not intended to become another generic web application firewall, a replacement for Apache, or a full-featured reverse proxy competing with HAProxy or Nginx.

We want a small, purpose-built security component with maximum control over inspection and mitigation behavior and a deliberately limited attack surface.

### Important architectural direction

The owner initially proposed using a lightweight Flask-style application to intercept traffic, inspect incoming requests using PoC-derived regular expressions, and forward legitimate traffic to Apache.

That idea has evolved during design discussions.

Flask itself is probably not the correct component for the public-facing gateway because Flask operates above an existing HTTP parser. By the time Flask receives a request, the underlying server has already processed the protocol framing.

However, **the desire to build our own small gateway remains the preferred direction**.

Use established, maintained TLS and HTTP protocol libraries. Do not implement TLS, HTTP/1.1 framing, HTTP/2 framing, HPACK, or similar protocol mechanisms from scratch.

We should own the inspection logic, security policies, vulnerability signatures, quarantine integration, backend routing, and deception decisions.

The development agent should evaluate Rust and Go, with Rust as an initial preference, but choose based on library capabilities, implementation complexity, security, performance, and maintainability.

Python should remain available for the existing controller and potentially an administrative control plane.

---

# 1. Why This Expansion Is Necessary

The existing Fleet-Filter architecture relies primarily on Apache to receive requests, inspect existing IP quarantine state, and divert classified sources into a separate deception responder.

Its present enforcement mechanism uses Apache `mod_rewrite`, a generated `RewriteMap`, and `mod_proxy`.

This architecture is effective for diverting already-classified scanners.

It cannot reliably protect Apache from vulnerabilities that execute before Apache's rewrite-processing stage.

## The motivating incident

A recently disclosed Apache HTTP/2 vulnerability, tracked in this project's research as CVE-2026-119618, motivated the original tarpit work.

The immediate mitigation involved removing HTTP/2 support from affected Apache configurations.

This is an acceptable emergency workaround, but it is not a satisfactory long-term solution.

Disabling HTTP/2 sacrifices legitimate protocol functionality and performance advantages. Additionally, HTTP/1.1 is not inherently more secure than HTTP/2; each protocol has its own vulnerabilities and implementation risks.

The real problem is not HTTP/2 specifically.

The real problem is that, when Apache itself contains a vulnerability, Apache's internal filtering mechanisms may be too late to prevent the vulnerable code from executing.

We want a protective layer that encounters the external request before Apache does.

## Generalized future scenarios

The gateway should accommodate vulnerabilities involving:

- HTTP/1.1 message framing and parsing.
- HTTP/2 frames, headers, streams, and request handling.
- Apache modules such as `mod_http2`, `mod_proxy`, `mod_ssl`, and other handlers.
- Malicious HTTP headers.
- Request paths, query strings, and encoded parameters.
- POST bodies and multipart requests.
- Malformed or unusual protocol transitions.
- Vulnerable PHP applications and CMS software.
- Known exploit payloads from publicly disclosed CVEs.
- Behavioral indicators of automated vulnerability scanning.

Not every vulnerability can be mitigated by a gateway. In particular, vulnerabilities in TLS implementations or the gateway's own protocol libraries may occur before custom inspection logic can execute.

The design must identify these limitations explicitly rather than claiming universal zero-day protection.

---

# 2. The Core Philosophy

There are two related but distinct goals.

## Goal A: Protect the real application

Prevent dangerous requests from reaching components known to be vulnerable.

Ideally, the gateway should recognize a malicious request before forwarding any relevant dangerous bytes or semantic content to Apache.

For protocol-level vulnerabilities, this may require the gateway to terminate the client protocol independently, validate it, and construct a separate upstream connection.

For application-level vulnerabilities, it may be sufficient to identify a dangerous URI, header combination, parameter, or request body before forwarding it.

The specific mitigation must be matched to the layer where the vulnerability exists.

## Goal B: Waste malicious scanners' time

When the gateway confidently identifies an exploit attempt, the request should normally be diverted into Fleet-Filter's existing deception system.

Rather than immediately rejecting the connection with a fast 403, 404, or reset, we want to consume the scanning tool's time and limited concurrency while using very little of our own infrastructure.

This follows the original LaBrea philosophy.

The desired response is usually a plausible, deliberately slow application interaction.

The exception is when resource exhaustion, malformed protocol handling, or another safety requirement makes continuing the interaction unsafe. In that situation, a cheap rejection is appropriate.

**Protection of the real service always takes precedence over deception.**

A malicious request must never fall through to Apache merely because the deception backend is unavailable.

---

# 3. Proposed Architecture

The new gateway becomes an optional front-end enforcement layer.

Conceptual flow:

```text
                         INTERNET
                            |
                            |
                     TCP / TLS / HTTPS
                            |
                            v
                +-----------------------+
                | Fleet-Filter Gateway  |
                |                       |
                | TLS termination       |
                | SNI / ALPN            |
                | HTTP/1.1 parser       |
                | HTTP/2 parser         |
                | Resource admission    |
                +-----------------------+
                            |
                            v
                +-----------------------+
                | Security Inspection   |
                |                       |
                | Protocol validation   |
                | Frame/event analysis  |
                | CVE signature matching|
                | Header/body inspection|
                | Existing IP reputation|
                +-----------------------+
                            |
                            v
                +-----------------------+
                | Policy Decision       |
                |                       |
                | ALLOW                 |
                | TARPIT                |
                | OBSERVE               |
                | REJECT (safety only)  |
                +-----------------------+
                            |
             +--------------+--------------+
             |                             |
           ALLOW                      TARPIT
             |                             |
             v                             v
    +------------------+        +------------------+
    | Apache HTTPD     |        | Fleet-Filter     |
    | Existing sites   |        | Deception Engine |
    | PHP / modules    |        | Slow responses   |
    | HTTP/1.1 or h2   |        | Fake applications|
    +------------------+        +------------------+

                 SHARED CONTROL PLANE
                            |
             +--------------+--------------+
             |              |              |
         Controller       Wazuh         Fail2ban
         SQLite state     Correlation   Behavioral
         Leases/claims    Detection     Detection
             |
         Fleet-wide
         Classification
```

The gateway is an enforcement component, not a new authoritative database.

The existing controller remains responsible for quarantine leases, evidence provenance, TTLs, allowlists, classification state, and fleet coordination.

The gateway should use an efficient local snapshot or cache of the controller's effective state so requests do not depend on a synchronous SQLite or network operation.

The existing Apache RewriteMap deployment should remain supported for environments where the gateway has not been installed.

We are adding an enforcement option, not invalidating the existing architecture.

---

# 4. Preserve Modern HTTP Functionality

This is a central design requirement.

**Do not solve every vulnerability by downgrading to HTTP/1.1.**

HTTP/2 provides important functionality, including multiplexing, header compression, and efficient reuse of connections.

HTTP/1.1 also has its own attack surface, including request-smuggling and message-framing ambiguities.

The gateway should support both protocols and preserve legitimate functionality whenever possible.

## Supported protocol combinations

The gateway should eventually support:

| Client connection | Gateway inspection | Backend connection |
|---|---|---|
| HTTP/1.1 | HTTP/1.1-aware | HTTP/1.1 |
| HTTP/2 | HTTP/2-aware | HTTP/2 |
| HTTP/2 | HTTP/2-aware | HTTP/1.1 |
| HTTP/1.1 | HTTP/1.1-aware | HTTP/2, if useful and supported |

Protocol selection should be configurable per backend, virtual host, or temporary mitigation policy.

When Apache is not vulnerable to a particular HTTP/2 issue, we should be able to continue using HTTP/2 on both sides.

When Apache's HTTP/2 implementation is vulnerable, the gateway should be able to accept HTTP/2 from external clients while communicating with Apache over a different protocol.

This preserves the client-facing advantages of HTTP/2, although it does not preserve HTTP/2 multiplexing across the backend connection.

It is also acceptable to temporarily disable a protocol entirely when no reliable selective mitigation exists.

Such a decision must be explicit and scoped as narrowly as possible.

Do not introduce a permanent HTTP/1.1-only limitation simply because the first motivating vulnerability involved HTTP/2.

HTTP/3 and QUIC should be considered future architectural extensions, not mandatory first-release features.

---

# 5. Custom Gateway Implementation

The owner prefers a small purpose-built gateway over introducing HAProxy or Nginx as mandatory infrastructure.

The rationale is not that a custom implementation is automatically safer.

It is that a narrowly scoped program may provide:

- Complete ownership of security decisions.
- Direct integration with Fleet-Filter's controller.
- Custom access to selected protocol-level events.
- A small, auditable feature set.
- Minimal operational dependencies.
- Precise control of which requests reach Apache.
- Tight integration between exploit detection and deception.
- Freedom to implement unusual protections for future vulnerabilities.

However, we must avoid replacing mature protocol parsing with hand-written parsers.

## Evaluate implementation languages

### Rust

Evaluate Rust using maintained asynchronous networking, TLS, and HTTP libraries.

Potential benefits include memory safety, controlled resource usage, low overhead, and access to lower-level protocol components.

Determine whether available HTTP/2 libraries expose enough protocol events to support the desired inspection before selecting one.

### Go

Evaluate Go's HTTP stack and lower-level HTTP/2 facilities as an alternative.

Go may simplify concurrency and maintenance, but the amount of control available at the HTTP/2 frame and stream level must be assessed.

### Python

Python remains appropriate for the controller and management operations.

A Python gateway using asynchronous networking and existing protocol libraries is possible, but must be evaluated against the expected request rates, memory consumption, connection counts, and inspection overhead.

Do not choose Flask merely because it is lightweight at the application layer.

## Required evaluation output

Before selecting the implementation stack, document:

1. Candidate languages and libraries.
2. TLS support and certificate handling.
3. HTTP/1.1 and HTTP/2 functionality.
4. Access to protocol-level events and original metadata.
5. Ability to inspect requests before upstream forwarding.
6. Streaming request and response support.
7. Connection and memory limits.
8. Security and fuzz-testing support.
9. Dependency complexity.
10. Measured or well-supported performance considerations.

Prefer maintained libraries with active security support.

Do not add a large framework merely to obtain a few useful functions.

---

# 6. Protocol-Aware Inspection

One of the main reasons for creating the gateway is to inspect more than Apache access logs expose.

The gateway should implement a layered inspection model.

## Layer 1: Connection and transport metadata

Inspect or record:

- Actual peer IP address.
- TLS SNI hostname.
- Negotiated ALPN protocol.
- TLS version and relevant negotiated parameters.
- Connection rate.
- Concurrent connections.
- Connection lifetime.
- Request and stream counts.
- Hostname consistency where applicable.

This information supports routing, policy, and behavioral analysis.

It should not automatically be treated as proof of malicious behavior.

## Layer 2: Protocol-level inspection

For HTTP/1.1:

- Request line validity.
- Message boundaries.
- Content-Length handling.
- Transfer-Encoding handling.
- Header syntax and size.
- Keep-alive behavior.
- Protocol upgrade requests.
- Ambiguous or conflicting framing.

For HTTP/2, investigate exposing:

- Frame type.
- Frame size.
- Stream ID.
- Stream lifecycle.
- HEADERS and CONTINUATION sequences.
- END_STREAM behavior.
- RST_STREAM events.
- SETTINGS and flow-control behavior.
- Header counts and decoded sizes.
- Abnormal stream transitions.
- Relevant timing and concurrency patterns.

The gateway should validate protocol state and reject malformed traffic according to the protocol's rules.

Avoid assuming every unusual frame sequence is malicious. Legitimate HTTP/2 implementations may exercise legal behavior in ways our initial tests do not anticipate.

## Critical technical limitation

A custom security rule cannot inspect a header until the protocol implementation has decoded enough of the incoming data to expose that header.

Similarly, an exploit affecting the gateway's own HTTP/2 decoder might execute before our custom inspection rule runs.

Therefore, protocol event visibility and vulnerability isolation must be treated separately.

For each proposed protection, identify the earliest point where the exploit's distinguishing characteristic is observable.

Do not claim a regex prevents a parser vulnerability unless its execution occurs before the vulnerable operation.

## Layer 3: HTTP request inspection

Inspect normalized:

- Method.
- Path and query string.
- Headers.
- Selected cookies.
- Content type.
- Request body, where supported and enabled.
- Multipart metadata.
- Relevant request trailers.

Support request-body inspection with strict limits.

Do not buffer arbitrarily large bodies in memory.

For a rule that requires examining the complete body before forwarding, use a bounded inspection buffer or an explicitly configured streaming inspection strategy.

Never forward potentially dangerous content before completing a required blocking inspection.

If a requested inspection cannot be performed, the policy must explicitly define whether to observe, reject, or use a documented mitigation fallback. It must not silently pretend the rule was enforced.

---

# 7. Vulnerability Signature Engine

Extend the existing:

`controller/signatures/signatures.yaml`

The existing project already separates known exploit signatures from behavioral scanner detection.

Retain that separation.

## Path A: Known exploit detection

Path A uses a high-confidence signature derived from known exploit behavior, ideally from a published PoC and independently validated fixtures.

A matching request can be classified immediately without waiting for repeated behavior.

However, signatures must be specific enough to distinguish exploitation from legitimate requests. A regex match alone does not guarantee malicious intent.

## Path B: Behavioral detection

Path B uses Wazuh, Fail2ban, and potentially gateway telemetry to identify scanning patterns over time.

A single suspicious URL, unusual header, or low-confidence match should not automatically cause an IP-wide quarantine.

Retain the existing distinction between confirmed exploit evidence and behavioral suspicion.

## Signature schema requirements

Each CVE policy should contain, where applicable:

- CVE identifier and description.
- Provenance of the PoC or research.
- Vulnerable software and affected versions.
- Vulnerability layer: protocol, module, or application.
- Affected virtual hosts or backend services.
- Multiple known exploit variants.
- Required inspection stage.
- Required protocol and metadata visibility.
- Match expressions or structured conditions.
- Positive and negative test fixtures.
- False-positive exclusions.
- Mitigation prerequisites.
- Whether mitigation is verified or only hypothesized.
- Residual risk and known bypass classes.
- Response profile.
- Classification confidence.
- Quarantine TTL.
- Creation and review dates.
- Rule owner and revision history.

Do not force every vulnerability into a regular expression.

Some vulnerabilities will require a structured combination of conditions, a protocol state machine, or a temporal sequence of events.

Others may only require a URI or header match.

The policy format should support this variation without becoming an unrestricted scripting engine in the request path.

## Rule actions

Support:

**Observe:** Record the match and supporting metadata without changing routing.

**Allow:** Permit the request to proceed.

**Tarpit:** Divert the request to the deception backend, subject to admission limits.

**Reject:** Use when required by protocol correctness, a safety invariant, or resource protection.

A known exploit detection should normally lead to a tarpit rather than an immediate block, following the existing project philosophy.

## Signature activation lifecycle

1. Import a PoC-derived detection rule.
2. Validate syntax and available inspection capabilities.
3. Run positive and negative tests.
4. Replay historical requests where available.
5. Operate in observe-only mode.
6. Review false positives and backend compatibility.
7. Promote explicitly to enforcement.
8. Monitor results.
9. Retire or revise stale signatures.

Prevent catastrophic regex backtracking and unbounded evaluation costs.

A signature requiring frame-level inspection must not be activated when the chosen protocol library exposes only reconstructed HTTP requests.

---

# 8. Request Reconstruction and Forwarding

The gateway should be capable of parsing and validating incoming requests and constructing clean upstream requests.

This is an important security feature.

Do not blindly relay arbitrary original client bytes into Apache.

The gateway should establish its own backend connection and produce protocol-compliant upstream messages.

## Required protections

- Reject ambiguous message framing.
- Normalize or validate request targets according to explicit policy.
- Apply correct hop-by-hop header handling.
- Prevent request-smuggling ambiguity between gateway and Apache.
- Enforce limits on headers, bodies, and streams.
- Preserve legitimate end-to-end headers.
- Prevent attacker-controlled destination selection.
- Avoid forwarding unvalidated protocol metadata.
- Support HTTP/2 pseudo-header validation and correct translation where necessary.
- Preserve application semantics rather than making aggressive transformations that break legitimate requests.

Do not assume normalization automatically removes application-layer exploits.

A syntactically valid SQL-injection payload remains a SQL-injection payload after reconstruction.

## Backend functionality

Maintain compatibility with common Apache-hosted applications:

- PHP.
- WordPress and other CMS software.
- Java application backends.
- Authentication and sessions.
- File uploads.
- Streaming responses.
- WebSockets where configured.
- Server-Sent Events.
- HTTP/2-dependent services such as gRPC where deployed.
- Redirects and application-generated absolute URLs.
- Range requests.
- Request and response trailers where required.
- Existing virtual hosts.

The gateway must not silently discard legitimate protocol features.

Where a feature is not yet implemented, document the limitation and reject unsupported usage safely.

---

# 9. TLS and Certificate Management

The gateway will generally need to terminate TLS to inspect encrypted HTTP requests.

Therefore, it requires certificates valid for the hostnames being protected.

Support these deployment options:

### Existing certificates

Allow the gateway to reuse existing Apache certificates and private keys, with appropriate permissions and lifecycle handling.

### Wildcard certificates

Support wildcard certificates where suitable.

Remember that a wildcard covering `*.example.edu` does not automatically cover the apex domain or deeper hostname levels.

### SAN certificates

Support certificates containing multiple hostnames.

### Multiple independent certificates

Use SNI to select among certificates for different virtual hosts.

## Operational requirements

- Secure private-key storage.
- Certificate reload without unnecessary downtime.
- Certificate expiration monitoring.
- ACME or existing enterprise certificate automation integration.
- TLS version and cipher configuration.
- Correct ALPN advertisement.
- No silent fallback to invalid certificates.
- Least-privilege access to certificate material.

Certificate management should be a small, separate subsystem rather than mixed into exploit matching.

A gateway deployed centrally for multiple servers concentrates private keys and therefore increases the impact of a gateway compromise. Document this tradeoff.

---

# 10. Client Identity and Proxy Headers

The gateway must preserve original client identity for Apache, access logs, Wazuh, rate limits, and quarantine decisions.

Potential mechanisms include:

- `X-Forwarded-For`
- `X-Forwarded-Proto`
- `X-Forwarded-Host`
- Standardized `Forwarded`
- PROXY protocol where supported

These mechanisms are not interchangeable, and the design must specify which one is authoritative.

## Security requirements

Never trust arbitrary forwarding headers supplied by internet clients.

The gateway must distinguish the actual connection peer from user-supplied claims of origin.

When generating forwarding metadata, replace or sanitize untrusted values.

Apache must trust forwarding data only from explicitly configured gateway addresses.

Support Apache `mod_remoteip` appropriately.

Direct connections to protected backend listeners must be prevented through binding restrictions, firewall rules, or network isolation.

Test spoofed forwarded headers to ensure an attacker cannot quarantine an arbitrary third party.

Account for legitimate shared NAT addresses, IPv6, and any trusted proxies already upstream.

Do not automatically expand a single IPv6 address into a broad network quarantine.

---

# 11. Integration With the Existing Controller

The new gateway must reuse the existing controller rather than creating an independent, competing quarantine database.

Current relevant components include:

- `controller/adaptive-tarpit.py`
- `controller/signatures/signatures.yaml`
- `detector/wazuh/`
- `detector/fail2ban/`
- `tarpit/server/server.py`
- `docs/DETECTION-INPUTS.md`
- `docs/FLEET-STATE.md`
- `SKILL.md`

The controller should remain the authoritative owner of claims and leases.

## Gateway classification integration

The gateway needs a local, efficient way to determine whether the current client is already quarantined.

This should not require a synchronous database query or remote network operation for every request.

Implement an efficient snapshot, map, or in-memory state mechanism with atomic updates.

The gateway should submit new high-confidence exploit detections to the controller asynchronously.

The triggering request must be diverted before it reaches Apache; it cannot wait for a future controller update to take effect.

## Classification and expiration

Preserve the project's intended policies:

- Suspect scanner leases use shorter TTLs.
- High-confidence exploit matches use longer TTLs.
- All ordinary quarantines expire.
- Local allowlists take precedence.
- Independent detector claims do not erase one another.
- Stronger evidence can promote an existing suspect lease.
- A successful empty lease state clears enforcement.
- A state retrieval failure must not be confused with a legitimate empty state.

## Existing review defects

The previous independent review identified problems that must not be carried into the new gateway integration:

1. Last-lease expiration leaves stale Apache routing state.
2. The Wazuh Active Response adapter mishandles the real message envelope.
3. Existing suspect leases are not reliably promoted by stronger evidence.
4. The responder can read production application source and follow unsafe filesystem paths.
5. Over-quota routing does not actually enforce resource backpressure.
6. POST body handling can desynchronize persistent connections.
7. Backend concurrency and resource limits are inadequate.
8. Detector classification and original-client attribution need improvement.

Treat these as existing project defects, not as features to reproduce in the gateway.

Where necessary, define explicit dependency work before enabling gateway enforcement.

---

# 12. Deception and Tarpit Integration

The new gateway should be capable of routing hostile traffic to the existing Fleet-Filter responder.

However, the existing responder needs security hardening before production use.

It must not read live PHP source, private application files, or arbitrary resources under Apache DocumentRoot.

Use bounded, prebuilt, sanitized deception profiles.

## Desired deception behavior

Depending on the detected exploit and policy, the responder might produce:

- Plausible administrative interfaces.
- Apparent application error messages.
- Fake version banners.
- Slow application responses.
- Controlled partial responses.
- Simulated vulnerable endpoints.
- Consistent fake application behavior across multiple requests.

The objective is to make automated scanners spend time investigating apparently meaningful results.

Do not collect credentials, execute attacker payloads, fetch attacker-selected URLs, or initiate connections back to scanners.

## Response strategy

Use different profiles for different vulnerability families.

A scanner testing an Apache HTTP/2 vulnerability should not necessarily receive the same fake application response as a scanner testing WordPress or a PHP configuration exposure.

Maintain consistent deception identity across hosts where appropriate.

The gateway should be able to select the appropriate profile based on the matched signature or existing classification.

## Resource-aware routing

The system must be able to select a cheaper response when the tarpit is approaching its budget.

For example:

- Full deception where resources permit.
- Minimal, bounded tarpit behavior under moderate load.
- Cheap failure or rejection when the defender is at risk.

The original project reserves rejection primarily for resource-budget backpressure, not ordinary hostile classification.

Preserve that policy while allowing mandatory protocol-safety rejection.

---

# 13. Resource Economics

The entire project depends on asymmetry.

**We should consume more scanner time than our own infrastructure resources.**

The gateway must not become an easy denial-of-service target.

## Required resource controls

- Global connection limits.
- Per-source connection limits.
- HTTP/2 concurrent-stream limits.
- Header count and size limits.
- Maximum inspected body size.
- Request and response timeouts.
- Idle connection timeouts.
- Memory limits.
- File-descriptor limits.
- Bounded inspection queues.
- Bounded controller event queues.
- Bounded tarpit response concurrency.
- Overload backpressure.
- Safe handling of slow clients.
- Safe handling of large uploads and streaming requests.

Avoid a thread-per-connection design where large numbers of hostile connections can exhaust system resources.

Prefer efficient asynchronous or event-driven I/O where appropriate.

Do not assume holding an HTTP/2 stream consumes the same resources as holding a whole TCP connection.

Measure actual costs.

## Important metrics

Track:

- Legitimate request latency.
- Requests per second.
- CPU and memory consumption.
- Open connections.
- Active HTTP/2 streams.
- Backend connection utilization.
- Gateway failures and 5xx rates.
- Inspection time per request.
- Signature-match overhead.
- Tarpit concurrency.
- Tarpit response durations.
- Scanner timeouts and abandonments.
- False-positive quarantine rate.
- Estimated scanner throughput reduction.

The project must not claim that a scanner's runtime has been reduced unless testing demonstrates it.

Many scanners are asynchronous and abandon slow requests quickly.

A long response is not automatically a successful tarpit.

---

# 14. Failure Handling and Isolation

The gateway introduces another component into the request path.

Its failures must be carefully defined.

## Required failure scenarios

Consider:

- Gateway crashes.
- Gateway restarts during active requests.
- Controller unavailable.
- SQLite database unavailable.
- Classification snapshot missing or stale.
- Tarpit backend unavailable.
- Apache backend unavailable.
- Signature compilation failure.
- Invalid configuration reload.
- TLS certificate unavailable.
- Resource exhaustion.
- HTTP/2 stream exhaustion.
- Excessive request-body buffering.
- Backend request timeout.
- Malformed or ambiguous HTTP requests.

## Critical invariants

A known quarantined source must never be forwarded to the production application because the tarpit is unavailable.

A signature requiring unavailable inspection capabilities must never be reported as actively protecting the server.

A corrupt configuration update must not replace a previously validated working policy.

A backend outage must not cause requests to be redirected to arbitrary destinations.

A gateway failure must not expose Apache's backend listener directly to the internet.

Where the system cannot make a safe decision, the behavior must follow an explicit documented policy.

Distinguish failure of the detector, failure of the controller, failure of the deception engine, and failure of the forwarding path. They should not automatically have identical consequences.

---

# 15. Deployment Architecture

Support two possible deployment models.

## Model A: Per-host sidecar gateway

Each Apache host runs its own gateway.

The gateway binds to public HTTP/HTTPS ports and forwards legitimate requests to Apache on an isolated local listener.

Advantages:

- Independent failure domains.
- Local certificates.
- Simple backend routing.
- Minimal network changes.
- No centralized gateway bottleneck.

This is the preferred initial implementation.

## Model B: Central security gateway

A dedicated Linux server or VM protects multiple Apache hosts.

The gateway terminates incoming connections, performs inspection, and routes traffic to the appropriate protected backend.

Advantages:

- Centralized signature enforcement.
- Stronger host separation.
- Potentially simpler fleet-wide management.
- Consolidated telemetry.
- Independent isolation from vulnerable Apache packages.

Disadvantages:

- Greater availability requirements.
- Centralized certificate handling.
- Additional network and routing considerations.
- Potential performance bottleneck.
- Larger failure blast radius.

For remote backends, define authenticated and encrypted upstream transport where required.

A central gateway must not become a single point of failure without an explicit high-availability strategy.

Do not implement the full central architecture as a prerequisite for the first sidecar prototype, but avoid design decisions that make it impossible later.

---

# 16. Configuration and Management

Keep administration simple.

Avoid creating an elaborate management platform before the gateway is proven.

Initially, use configuration files, command-line tooling, existing logs, and systemd.

Configuration should support:

- Listening ports and interfaces.
- TLS certificates and SNI mappings.
- Backend destinations.
- Supported protocols.
- Per-vhost mitigations.
- Signature policy activation.
- Local allowlists.
- Controller integration.
- Resource limits.
- Deception routing.
- Logging and telemetry.
- Observe-only mode.
- Emergency bypass and rollback behavior.

A lightweight Flask or FastAPI administrative interface could be considered later.

Such an interface must not sit in the critical forwarding path.

## Observability

Emit structured events containing:

- Timestamp.
- Actual client IP.
- Virtual host.
- Protocol.
- Signature or policy identifier.
- Detection stage.
- Decision taken.
- Backend or tarpit destination.
- Confidence and evidence reference.
- Request correlation ID.
- Relevant latency and resource metrics.

Bound and sanitize all attacker-controlled data.

Do not log raw credentials, session cookies, authorization tokens, or unbounded request bodies.

Preserve compatibility with Wazuh ingestion.

---

# 17. Security Requirements for the Gateway Itself

This must be a hardened internet-facing service.

Requirements include:

- Least-privilege execution.
- No unnecessary root privileges.
- Restricted backend connectivity.
- No arbitrary URL fetching.
- No open-proxy behavior.
- No dynamic execution of request data.
- Minimal exposed management interfaces.
- Constrained filesystem access.
- Safe certificate-key permissions.
- Strong separation between data plane and control plane.
- Strict resource limits.
- Safe configuration reload.
- Dependency auditing.
- Protocol fuzz testing.
- Request-smuggling testing.
- Concurrency testing.
- Memory and file-descriptor monitoring.

Investigate suitable systemd sandboxing and SELinux policies for Oracle Linux deployments.

The gateway must not weaken the existing host security posture.

Importantly, the mere presence of a custom gateway does not make the infrastructure immune to zero-days.

The gateway's TLS and HTTP libraries become part of the exposed attack surface.

The engineering objective is to create a small, well-tested, independently patchable boundary that can shield Apache-specific vulnerabilities and enforce targeted mitigations.

---

# 18. Testing Strategy

Testing is a first-class project deliverable.

The gateway should have unit, integration, security, compatibility, and load tests.

## Unit tests

Test:

- Configuration parsing.
- Signature compilation.
- Positive and negative signature fixtures.
- Routing policies.
- Claim submission.
- Quarantine state lookup.
- Allowlist precedence.
- TTL handling.
- Client identity validation.
- Resource-budget decisions.

## Protocol tests

Test legitimate and malformed HTTP/1.1 and HTTP/2 traffic.

Include:

- Conflicting content lengths.
- Transfer-Encoding ambiguity.
- Invalid headers.
- HTTP/2 frame sequences.
- Stream resets.
- Header continuations.
- Request trailers.
- Large header sets.
- Flow-control edge cases.
- Connection shutdown.
- Backend protocol translation.
- HTTP/2 concurrent streams.

Use maintained protocol test tools and fuzzers where appropriate.

## Compatibility tests

Test representative real applications behind Apache.

Verify authentication, sessions, redirects, uploads, WebSockets, streaming, and normal browser behavior.

A gateway that blocks exploits but breaks common production functionality is not ready for deployment.

## Zero-day mitigation simulation

Create an isolated laboratory scenario using a known, safely reproducible vulnerability or a purpose-built vulnerable test backend.

Demonstrate:

1. The unprotected backend receives the dangerous request.
2. The gateway recognizes the defined threat condition, or isolates the vulnerable protocol operation.
3. The protected backend does not execute the vulnerable path.
4. The gateway emits a correct detection event.
5. The originating request is diverted or safely rejected.
6. A subsequent request follows the correct quarantine policy.
7. Legitimate traffic continues to work.

Distinguish PoC-pattern detection from general exploitation prevention. A successful signature test does not establish immunity to variant payloads.

Do not run exploit reproduction against production university systems.

## Performance tests

Compare:

- Direct Apache.
- Apache with existing RewriteMap tarpit integration.
- Apache behind the new gateway with inspection disabled.
- Apache behind the gateway with inspection enabled.
- Gateway with active deception traffic.

Measure latency distributions, throughput, resource consumption, and overload behavior.

Maintain separate results for HTTP/1.1 and HTTP/2.

The gateway should have explicit acceptance thresholds based on the actual environment rather than arbitrary performance promises.

---

# 19. Implementation Roadmap

Develop this incrementally.

## Phase 0: Project inspection and architecture decision

Inspect the existing repository, especially `SKILL.md`, `docs/HANDOFF.md`, `docs/DETECTION-INPUTS.md`, `docs/FLEET-STATE.md`, and the independent review findings.

Identify reusable components and unresolved defects.

Evaluate Rust, Go, and their relevant TLS/HTTP libraries.

Produce the architecture decision with explicit tradeoffs.

## Phase 1: Minimal gateway prototype

Create a standalone gateway capable of:

- Accepting TLS connections.
- Serving HTTP/1.1 and HTTP/2 clients.
- Selecting certificates through SNI.
- Forwarding legitimate requests to a configured Apache backend.
- Preserving client identity safely.
- Enforcing basic protocol and resource limits.
- Logging structured request metadata.

Initially, use simple static routing and inspect-only instrumentation.

Do not make deception a prerequisite for validating the basic gateway.

## Phase 2: Inspection framework

Implement:

- Protocol event adapters.
- Structured request inspection.
- Signature policy loading.
- Rule validation.
- Observe-only mode.
- Deterministic policy decisions.
- Positive and negative fixtures.
- Safe atomic configuration reload.

Establish exactly what the protocol libraries expose and when.

## Phase 3: Inline enforcement

Allow validated signatures to prevent forwarding of matching dangerous requests.

Demonstrate that an inline decision happens before the relevant backend action.

Support both HTTP/1.1 and HTTP/2 as appropriate.

## Phase 4: Fleet-Filter integration

Integrate:

- Existing controller state.
- Local quarantine cache.
- Asynchronous new-claim submission.
- Allowlist enforcement.
- Expiration.
- Wazuh audit events.
- Deception backend routing.
- Resource-aware tarpit admission.

Fix relevant existing controller and responder defects before relying on those components.

## Phase 5: Vulnerability-specific mitigation policies

Build policies for representative vulnerabilities at different layers:

- Protocol-level.
- Apache module-level.
- Application-level.

Demonstrate what the gateway can prevent, what it merely detects, and what remains outside its protection boundary.

## Phase 6: Hardening and performance

Perform security testing, fuzzing, load testing, protocol compatibility testing, and resource-economics measurements.

Establish production acceptance criteria.

## Phase 7: Limited deployment

Deploy as an isolated canary before production.

The repository currently describes `lab-web01.lab` as the existing tarpit test host. Use that context for planning, but verify the current environment and choose an appropriate HTTP/2-capable laboratory target for protocol-specific work.

Do not alter existing live listeners, certificate bindings, firewall exposure, or production Apache routing without an approved rollout and rollback plan.

## Phase 8: Fleet and central-gateway capabilities

Only after the sidecar gateway is stable, investigate:

- Fleet-wide policy distribution.
- Central gateway mode.
- Cross-host response consistency.
- Coordinated quarantine.
- High availability.
- Automated certificate management.
- Gateway health dashboards.

---

# 20. Explicit Non-Goals

Do not:

- Replace Apache's application-serving responsibilities.
- Rewrite existing websites.
- Implement a new TLS stack.
- Implement a complete HTTP parser from scratch.
- Disable HTTP/2 globally as the permanent architecture.
- Make HAProxy or Nginx mandatory.
- Put Flask in the public-facing request path without a compelling technical justification.
- Build a general-purpose open proxy.
- Add an unrestricted scripting engine to the request hot path.
- Execute attacker-supplied content.
- Fetch attacker-supplied URLs.
- Forward untrusted client identity headers as authoritative.
- Store raw secrets in request telemetry.
- Introduce an unbounded thread-per-connection tarpit.
- Claim a mitigation works merely because a regex matches.
- Automatically enable untested exploit signatures.
- Rewrite the existing Fleet-Filter controller unnecessarily.
- Build a complex web dashboard before the core gateway works.
- Make live production infrastructure changes without appropriate validation and authorization.

---

# 21. Required Deliverables From the Development Agent

Begin by producing:

**A. Architecture assessment**

Explain the proposed gateway components, the trust boundaries, the external library choices, and the expected limitations.

**B. Technology recommendation**

Compare Rust and Go for the actual protocol access and security behavior required here. Recommend one with supporting reasoning.

**C. Repository integration plan**

Identify new directories, modules, interfaces, and modifications to existing Fleet-Filter code.

Do not create a parallel, incompatible classification system.

**D. Threat model**

Identify attacks against Apache, attacks against the gateway, attacks against the tarpit, spoofed identities, control-plane compromise, resource exhaustion, and policy bypasses.

**E. Inspection capability matrix**

For each relevant protocol or vulnerability layer, identify what is observable, when it becomes observable, what mitigation is possible, and what residual risk remains.

**F. Implementation backlog**

Provide an ordered set of development tasks with dependencies and test criteria.

**G. Prototype implementation**

Once the architecture is established, begin implementing the minimal gateway and its automated tests.

**H. Validation report**

Clearly distinguish implemented functionality, passing tests, demonstrated security properties, assumptions, limitations, and outstanding work.

Avoid replacing actual tests with architectural assertions.

---

# 22. Final Design Principles

The following principles should guide every implementation decision.

**1. Preserve functionality whenever possible.**

A security gateway should not force unnecessary protocol downgrades or disable useful features simply because one backend implementation has a vulnerability.

**2. The gateway must encounter dangerous input before the protected component does.**

Otherwise it may provide detection and deception, but not mitigation.

**3. Own security policy, not cryptographic or protocol primitives.**

Implement our own inspection and enforcement logic using established protocol libraries.

**4. A PoC signature is evidence, not universal protection.**

Document exactly which exploit conditions are detected and what variants could bypass the rule.

**5. Separate protection from deception.**

A request may be detected, safely isolated, and tarpitted, but these are distinct operations with independent success conditions.

**6. Avoid creating a more dangerous attack surface.**

The gateway must be simpler, more constrained, and better tested than an unconstrained custom web server.

**7. Preserve the existing Fleet-Filter philosophy.**

Make automated hostile scanning expensive in attacker time while keeping defender resource consumption low.

**8. Keep components independently replaceable.**

The protocol handling library, gateway, signature engine, controller, and deception backend should have clearly defined interfaces.

**9. Be operationally conservative.**

Existing Apache sites, certificates, authentication, application behavior, and routing must continue working.

**10. Measure protection and performance rather than assuming them.**

The project succeeds only if real testing demonstrates improved security without unacceptable availability or performance costs.

---

# Final Instruction to the Agent

Treat this as a serious security architecture project, not simply a reverse-proxy coding exercise.

Begin by reading and understanding the existing Fleet-Filter repository and its design decisions. In particular, distinguish documented intentions from implemented functionality.

Produce a critical architecture assessment and evaluate the implementation choices before committing to a protocol stack.

Challenge any requirement that cannot be implemented safely or whose protection claims cannot be demonstrated.

Once a defensible architecture is established, implement it incrementally with reproducible tests.

**The intended end state is a small, independently maintainable security gateway that can absorb and inspect external HTTP traffic, apply narrowly targeted vulnerability mitigations, preserve HTTP/2 and other legitimate functionality where safe, forward benign traffic to Apache, and divert confidently identified exploit attempts into the existing Fleet-Filter deception system.**

The goal is not to make Apache invulnerable.

The goal is to give us an independent, programmable protective boundary so that the next serious Apache or application zero-day does not leave us with only two choices: disable major functionality or wait for a vendor patch.

## Certificate custody and renewal (2026-11-24)

The gateway terminates TLS, so it holds the site certificate. That is not a new decision to make -
the deployed lab-web01 listener already presents an InCommon RSA Server CA 2 certificate for
CN=lab-web01.lab, valid to 2026-02-28. The burden moved to the gateway at deployment; what
was missing was ownership of the renewal.

**Fixed: a renewal used to be silently swallowed.** `reload()` short-circuited on
`policy_line() == policy_line()`, and that line is the bundle digest - the certificate and key are
*named* in the bundle, not carried in it. Replacing the files left the line identical, so SIGHUP
logged `policy reload: unchanged` and the old certificate kept being served until a restart. A
renewal that reports success and does nothing is worse than no procedure.

The reload decision now compares a digest of the certificate and key bytes as well, and names the
change in the journal:

```
policy reload ok: policy version=... sha256=... (tls material changed, now 3f2a1c0d9e8b)
```

Measured end-to-end: replaced the certificate file, sent SIGHUP, and the served subject changed from
CN=ff-lab-gateway to CN=renewed.example on a new connection with no restart. Connections already
open keep the material they were accepted with, which is the intended swap semantics.

**Still missing, and it is operational rather than code:**

* No renewal tooling. Nothing in the repo runs an ACME client or reaches InCommon's flow, and
  nothing watches `notAfter`. The 2026-02-28 expiry is currently unmonitored.
* HTTP-01 needs port 80 reachable on the gateway; DNS-01 needs a credential. Neither is wired.
* Key custody: the private key is now on a host that is not the web server, owned by the gateway's
  user, mode 600. That host is secret-bearing and has to be treated as such.
* One certificate per listener. Multiple vhosts need multiple listeners or a SAN/wildcard cert;
  SNI-based selection is not implemented, and neither is client-certificate (mTLS) verification.

## Behind a load balancer (2026-11-24)

In the deployed estate most certificates live on the F5, not on the web host, and the F5 was verified
to pass the correct client address. That is necessary but was not sufficient: the gateway did not read
the header at all, and keyed every decision on the peer address, which behind an F5 is the F5.

Three failures followed from one architectural fact:

* `max_connections_per_source = 16` applied to the balancer, so the seventeenth concurrent connection
  for the whole site was closed.
* A single detection memoised the balancer as tarpitted, so every client behind it received deception.
* Claims named the balancer, so a controller drain would quarantine it - and the balancer's own health
  check would then be dripped, marking the pool member down.

`[listener] trusted_proxies` now names the prefixes whose forwarding header is believed. Matching is
right-to-left and skips trusted hops, because a proxy appends what it saw and the leftmost entries are
whatever the client chose to send. A peer outside the list cannot name itself. The per-source
connection cap is not applied to a trusted proxy (it multiplexes); the global cap still is.

Measured, one balancer address `127.0.0.1` with `trusted_proxies = ["127.0.0.1/32"]`:

| request | result |
|---|---|
| client A (`.50`) sends traversal | detected, `claim=prefix:/cgi-bin/.%2e`, log `peer=127.0.0.1 source=203.0.113.50` |
| client B (`.51`), same peer, ordinary | 200, unaffected |
| client A again, ordinary | 403 generic - the memo is keyed on A, not on the balancer |
| untrusted `127.0.0.2` claiming to be A | claim records `127.0.0.2`; the header was ignored |
| 20 concurrent connections via the trusted peer | 20 of 20 accepted (cap is 16 per source) |

An empty `trusted_proxies` keeps the gateway's edge behaviour: the peer address is the client address.

**Still open and needs the F5 configuration, not a code change:** if the virtual server terminates TLS
and speaks HTTP/1.1 to the pool, the gateway never sees HTTP/2, so the h2 protocol shapes cannot fire in
production - the h2 attack surface belongs to the F5. If the F5 is configured for HTTP/2 to pool members,
they apply. Which one is configured decides whether the shapes are load-bearing or lab-only.
