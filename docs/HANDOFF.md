# Project Handoff: Adaptive HTTP/HTTPS Tarpit and Scanner Quarantine System

**Working name:** Adaptive Web Tarpit (project name in use: **Fleet Filter**)
**Date:** November 12, 2026
**Status:** Architecture and implementation planning
**Primary environment:** Apache HTTP Server 2.4, Oracle Linux 8/9 and other Linux hosts, Wazuh, firewalld/nftables, optional Fail2ban
**Reference project:** https://github.com/crumrine/web-tarpit

> Provenance: this is the architecture brief received from the owner (developed with
> ChatGPT), stored verbatim as the project specification. Inline image/favicon artifacts
> from the source document have been removed; the text and tables are unchanged.
> Operational knowledge and later corrections live in `../SKILL.md`.

---

## 1. Executive Summary

We want to develop an Apache-integrated, security-event-driven HTTP/HTTPS tarpit system that automatically identifies internet vulnerability scanners and temporarily diverts their subsequent web requests into deliberately slow, misleading, resource-efficient HTTP interactions.

The inspiration is **LaBrea**, the old TCP tarpit application, but adapted to modern HTTP/1.1, HTTP/2, HTTPS, reverse proxies, and automated vulnerability scanners.

The central philosophy is straightforward:

**An automated vulnerability scanner should not necessarily receive an immediate 403, 404, or connection reset. Once we have confidently classified it as hostile scanning traffic, we would rather consume its scanning time and limited concurrency, while expending minimal resources ourselves.**

For example, a scanning tool that normally tests 100 URLs in a few seconds might instead spend substantial time waiting for plausible application responses that arrive extremely slowly.

We are particularly interested in scanners that attempt to locate vulnerable web applications, exposed configuration files, outdated software, administrative interfaces, WordPress installations, PHP shells, Java applications, and known exploit endpoints.

This is a defensive deception and resource-delay system, not an offensive tool. It must not send attacks back to source machines, exploit their software, or initiate unsolicited connections to them.

### Desired high-level behavior

1. A scanner begins requesting suspicious URLs from one of our public web servers.
2. Apache logs the requests, and Wazuh, Fail2ban, or another detector identifies a sufficiently high-confidence scanning pattern.
3. The detector places the offending source IP into a temporary quarantine/tarpit classification.
4. Apache recognizes that IP on subsequent requests.
5. Instead of passing those requests to the legitimate application, Apache routes them to a local HTTP tarpit service.
6. The tarpit returns convincing fake responses, extremely slow data streams, fake application interfaces, or other controlled delays.
7. The attacker remains occupied until it times out, abandons the connection, or finishes the deliberately prolonged response.
8. After a configured period, the quarantine automatically expires.
9. The address returns to ordinary processing unless additional hostile behavior is detected.

The system should be automated, observable, reversible, inexpensive to operate, and designed for unattended production use.

**Most importantly, the defense must never consume more critical resources than the traffic it is attempting to inconvenience.**

---

## 2. Original Motivation and Spirit of the Project

Historically, LaBrea exploited characteristics of TCP to keep hostile connections occupied.

The general idea was to make a scanning machine spend significantly more resources or time interacting with the defender than the defender spent responding.

With modern vulnerability scanners, the same principle may be applicable at the HTTP application layer.

Consider a scanner requesting:

- `/.env`
- `/.git/config`
- `/wp-login.php`
- `/wp-admin/`
- `/xmlrpc.php`
- `/phpmyadmin/`
- `/vendor/phpunit/`
- `/cgi-bin/`
- `/shell.php`
- `/actuator/health`
- Known CVE-specific paths

The usual production web-server behavior is to return 403, 404, or another quick response.

That is operationally efficient for both sides.

The scanner learns that the endpoint is unavailable and immediately moves on.

Our proposed response is different.

Once the source is confidently identified as an abusive scanner, we can present an apparent exposed application, configuration file, or administrative interface, then take an intentionally unreasonable amount of time to complete responses.

We want to exploit the scanner's own assumptions:

- Some tools wait for an HTTP response before continuing.
- Some scanners have limited concurrent request slots.
- Some scanners allocate one worker per active request.
- Some tools retry requests that appear promising.
- Some automated exploration tools follow links or investigate apparent exposed applications.
- Some scanners will spend considerable time downloading what appears to be sensitive information.

We should not assume all scanners behave this way. Many enforce strict timeouts, cancel slow requests, or use asynchronous networking.

Therefore, this should be treated as an experimentally testable defense, not an assumed guarantee of resource exhaustion.

We want to measure whether we actually increase scanner completion time and reduce successful scan throughput.

The project's purpose is **to make opportunistic automated scanning less efficient without increasing the risk to the defended applications.**

---

## 3. Essential Architectural Requirements

### 3.1 Apache remains the production web server

The administrator does not want to replace Apache with HAProxy, Nginx, or an entirely new JavaScript web stack.

The existing Apache configuration should continue serving the real websites.

We should not have to modify every PHP application, WordPress installation, Java application, or other service.

We should not run all legitimate website requests through a Node.js application.

The preferred design places a lightweight routing decision inside Apache and delegates slow HTTP generation to a separate local process.

### 3.2 Wazuh is the preferred detection integration

Wazuh is already part of the environment.

We want it to detect suspicious activity and trigger a temporary response.

Fail2ban should also be considered as a simpler, independent integration.

The tarpit should not depend on one particular detection engine. Detection should produce a normalized event, and a common quarantine controller should handle the rest.

### 3.3 Per-IP quarantine

The primary trigger should be an already-classified source IP address.

The initial detection may be based on suspicious URLs, request rates, ModSecurity events, or correlated Wazuh alerts.

However, once the source is quarantined, subsequent HTTP requests from that IP should receive tarpit treatment even if they request an otherwise legitimate URL.

This is important.

If an attacker is only trapped when requesting `/.env`, but the next request to `/` gets an immediate legitimate response, the tool is not providing the desired IP-based quarantine behavior.

### 3.4 Temporary enforcement

Every quarantine entry must have an expiration time.

Permanent quarantines should not be the default.

The controller should support:

- Adding an IP
- Removing an IP
- Extending an existing quarantine
- Checking whether an IP is quarantined
- Listing active quarantines
- Recording why an IP was quarantined
- Automatically expiring entries
- Manually overriding a classification
- Maintaining allowlists and exclusions
- Disabling all tarpit routing immediately

### 3.5 No public tarpit port

The tarpit backend should listen on loopback, a Unix-domain socket, or another explicitly restricted interface.

It must not expose a second public HTTP service by accident.

Apache should connect to it internally.

### 3.6 Minimal interference with legitimate services

Normal visitors should encounter minimal processing overhead beyond a fast classification lookup.

The existing Apache configuration, authentication, PHP handling, application routing, certificates, and other functionality must continue working.

Any change to the request path must occur only after a source is classified.

The design should favor a small, isolated integration over extensive modifications to existing application configurations.

---

## 4. Primary Architecture: Apache + Dynamic IP Classification + Local Tarpit

This is the preferred initial architecture.

```
                     INTERNET
                        |
                        |
                 HTTPS / HTTP
                        |
                        v
               +------------------+
               | Apache HTTPD     |
               | Existing :443    |
               | TLS termination  |
               +------------------+
                        |
                        v
               +------------------+
               | mod_rewrite      |
               | IP classification|
               | lookup           |
               +------------------+
                        |
               +--------+---------+
               |                  |
         NOT QUARANTINED      QUARANTINED
               |                  |
               v                  v
       +----------------+  +------------------+
       | Existing       |  | mod_proxy        |
       | Production     |  | Internal request |
       | Website        |  | redirection      |
       +----------------+  +------------------+
                                  |
                                  v
                         +------------------+
                         | Local HTTP       |
                         | Tarpit service   |
                         | 127.0.0.1:3001   |
                         +------------------+
                                  |
                                  v
                         Slow/fake HTTP
                         response stream


           DETECTION / CONTROL PLANE

       Apache logs / ModSecurity
                    |
                    v
             Wazuh / Fail2ban
                    |
                    v
            Quarantine Controller
                    |
                    v
         Dynamic IP classification
                    |
                    v
          Apache routing decision
```

Apache should remain unaware of the internals of the tarpit response generator.

It should only need to determine whether a request is allowed to continue normally or needs to be handled by the isolated tarpit backend.

The backend can be implemented using the existing `web-tarpit` package, a fork, or a custom minimal server.

The preferred first implementation is to adapt the existing project rather than immediately writing a completely new engine.

---

## 5. Upstream Reference: crumrine/web-tarpit

Repository: https://github.com/crumrine/web-tarpit

Relevant source:

- https://github.com/crumrine/web-tarpit/blob/main/src/tarpit.js
- https://github.com/crumrine/web-tarpit/blob/main/src/adapters.js

### 5.1 What the project provides

At the time of this handoff, the upstream package provides:

- HTTP path-based bot-probe detection
- Fake WordPress login pages
- Fake WordPress administrative pages
- Fake environment-file contents
- Fake Git configuration files
- XML-RPC fault responses
- Optional XML-RPC honeypot responses
- Slow-drip HTTP response streaming
- Trap-event callbacks
- Node.js and Express adapters
- Integration with the standard JavaScript Request/Response API

The package has no external runtime dependencies and targets Node.js 18 or newer.

Its slow-response implementation sends small chunks, typically three bytes at a time, with randomized delays of approximately 100-500 milliseconds.

A small response can consequently occupy a client for tens of seconds.

### 5.2 What it does not provide

This is important.

The project is not a complete standalone security gateway.

It does not automatically:

- Monitor Apache logs
- Receive Wazuh alerts
- Manage temporary IP bans
- Maintain persistent quarantine state
- Install Apache routing rules
- Modify firewalld rules
- Handle arbitrary URLs from already-quarantined clients
- Enforce our desired per-IP resource budgets

Its principal `tarpit()` function evaluates the requested URL path.

For a recognized suspicious path, it returns a response.

For an unrecognized path, it returns `null`.

That is appropriate when the library is installed inside a JavaScript application that normally handles other requests.

It is not sufficient by itself for our desired deployment.

We need an additional system to decide when to divert an entire source IP to the tarpit.

### 5.3 Important implementation observations

The source contains a predefined list of suspicious URL paths.

The path matcher is broader than some of the actual response-generating branches.

Certain paths can be recognized by the matcher and still fall through without producing a response.

The upstream documentation and actual behavior should therefore be tested rather than assumed identical.

Also, the package's IP-identification logic examines headers such as `CF-Connecting-IP` and `X-Forwarded-For`.

In our environment, such headers must not be treated as authoritative unless the upstream proxy chain is trusted and properly configured.

Otherwise, an attacker might supply spoofed headers.

The upstream code also supports credential-capture callbacks for honeypot interactions.

We should disable or redact sensitive captured data by default. We do not want this project to become a plaintext credential repository.

### 5.4 Recommended integration

Initially, create a small local Node.js service that imports the existing package.

Run it independently from Apache under systemd.

Use the package's existing responses when appropriate.

For requests that do not match an existing trap path, implement a controlled fallback response or internally map the request to a known tarpit endpoint.

For example, Apache could send every quarantined request to an internal `/.env` response endpoint in the initial proof of concept.

That is sufficient to prove the quarantine and slow-response mechanism.

However, it loses the original request path and makes all trapped responses look alike.

A later version should preserve the original request context and select a convincing response based on URL, method, and configured deception profile.

### 5.5 Fork versus wrapper

Prefer a wrapper for the initial implementation.

Do not fork the entire upstream project unless necessary.

If the library's behavior requires direct modifications, maintain a clearly documented fork or vendor a pinned version under its MIT license.

Pin the dependency to a reviewed version or commit.

Audit any changes upstream before upgrading.

---

## 6. Apache Integration Strategy

### 6.1 Preferred Apache modules

Investigate use of: `mod_rewrite`, `mod_proxy`, `mod_proxy_http`, `mod_remoteip` (if a trusted reverse proxy or load balancer exists), `mod_headers` where needed for request metadata or safe header handling.

No custom compiled Apache module should be required for the initial version.

### 6.2 Dynamic IP map

Use Apache's `RewriteMap` feature to maintain an IP-to-classification mapping.

Example: `/etc/httpd/tarpit-ips.map`

```
198.51.100.23 1
203.0.113.45 1
2001:db8::1234 1
```

The addresses above are documentation examples.

An entry with value `1` indicates an IP requiring tarpit treatment.

Absence from the map indicates ordinary handling.

Apache supports changing a text-based RewriteMap while running.

Its lookup cache uses the mapping file's modification time to detect changes.

This allows the controller to modify quarantine membership without restarting or reloading Apache for each event.

We must verify the exact behavior on the target Oracle Linux Apache version, including rapid successive updates and filesystem modification-time behavior.

### 6.3 Illustrative Apache configuration

The following is a conceptual starting point, **not a drop-in production configuration**.

```apache
# Server or VirtualHost context, not .htaccess

ProxyRequests Off

RewriteEngine On

RewriteMap tarpit_ips \
    "txt:/etc/httpd/tarpit-ips.map"

# A source IP present in the map is diverted.
RewriteCond "${tarpit_ips:%{REMOTE_ADDR}|0}" "=1"

RewriteRule "^" \
    "http://127.0.0.1:3001/.env" [P,L,QSD]
```

This demonstrates the desired behavior:

1. Apache gets the request's client IP.
2. Apache checks the map.
3. If the IP is listed, Apache proxies the request internally.
4. If it is absent, existing processing continues.

In the proof of concept, the proxy target is a fixed local URL. This is intentional: no user-controlled hostname should influence the proxy destination.

The agent must validate the exact directive syntax, configuration scope, interactions with existing rewrites and `ProxyPass` rules, and whether this rule executes at the appropriate stage for all protected applications.

### 6.4 Configuration placement

We should prefer a reusable Apache configuration include.

Possible location: `/etc/httpd/conf.d/adaptive-tarpit.conf`

However, the integration may need virtual-host-specific placement to ensure the rewrite rule executes before other routing rules.

The agent should investigate the current Apache configuration before selecting the final location.

The design must accommodate multiple virtual hosts on one server.

Avoid requiring the administrator to manually paste large configuration blocks into every website.

### 6.5 Update behavior

The controller should update the mapping file safely.

Required properties:

- Idempotent updates
- Atomic file replacement
- Correct ownership and permissions
- No partially written maps
- Concurrency-safe updates
- Preservation of existing entries
- Correct handling of IPv4 and IPv6
- Reliable detection of file modification
- No Apache restart for ordinary membership changes
- Recovery after controller or host restart

A reasonable strategy is to maintain authoritative quarantine state separately, generate a complete temporary map, validate it, and atomically replace the active map.

Do not use uncontrolled concurrent append operations on the active Apache map.

The controller should also confirm that Apache actually observes membership changes within the expected time.

### 6.6 Proxy behavior

The agent must test: HTTP/1.1, HTTP/2, GET, POST, HEAD, large request bodies, chunked responses, connection cancellation, keep-alive, backend crashes, backend timeouts, client disconnects, concurrent requests, WebSocket or upgrade requests where applicable.

A particularly important question is whether Apache forwards small response chunks promptly or buffers/coalesces them.

The upstream JavaScript code generating three-byte chunks does not guarantee that the remote scanner receives three-byte network writes.

Apache's proxying behavior, TLS layer, HTTP version, and operating-system buffering may affect the observable response.

Measure this rather than guessing.

Also verify that downstream `Transfer-Encoding` handling is correct, particularly for HTTP/2, where HTTP/1.1 hop-by-hop framing headers are not appropriate.

---

## 7. Wazuh Integration

Wazuh should be our primary automation framework.

Official documentation:

- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/how-to-configure.html

### 7.1 Intended behavior

Wazuh receives Apache and other security logs.

Rules identify suspicious behavior.

A high-confidence alert launches a custom Active Response script.

The script extracts the verified source IP and relevant metadata.

The script passes the information to the quarantine controller.

The controller updates the active classification.

When the specified penalty expires, the IP is released automatically.

### 7.2 Custom Active Response

Wazuh custom Active Response scripts receive structured JSON through standard input.

Stateful active responses support `add` and `delete` operations.

Their configuration specifies which alerts trigger the response, where the script executes, and how long the response remains active.

We should write a dedicated integration rather than modify Wazuh's generic firewall-drop response.

Suggested name: `adaptive-tarpit-ar`

Possible responsibilities:

1. Read Wazuh JSON from standard input.
2. Validate the message.
3. Extract the source IP.
4. Validate that the address is a legitimate IPv4 or IPv6 address.
5. Identify the rule that triggered the response.
6. Check applicable exceptions.
7. Add or update quarantine state.
8. Log the action.
9. Correctly handle a later release operation.
10. Return a valid result to Wazuh.

Follow Wazuh's documented duplicate-key handshake and its line-oriented input/output protocol.

Avoid blindly copying example scripts without understanding the installed Wazuh version.

### 7.3 Independent expiration is recommended

Although Wazuh supports timed active responses, the quarantine controller should also maintain its own expiration timestamps.

There are several reasons:

- An IP may generate another alert while already quarantined.
- The penalty may be extended.
- A Wazuh process may restart.
- A delayed release event may arrive after a newer quarantine was created.
- Fail2ban may independently classify the same IP.
- The host may reboot.

The authoritative controller should only release an IP when no active classification or hold remains.

A stale `delete` event must not prematurely cancel a newer quarantine.

### 7.4 Detection scope

Wazuh should be configured to detect web vulnerability probing from Apache logs, ModSecurity alerts where present, and other relevant security telemetry.

We should initially prioritize high-confidence patterns, not indiscriminately tarpit every 404.

Potential signals include:

- Several distinct sensitive-file probes within a short window
- Repeated attempts to access known exploit endpoints
- Requests associated with vulnerable software absent from the site
- Repeated probing of known remote-code-execution paths
- Automated scanning across unrelated application technologies
- Excessive suspicious requests from a single address
- Correlated ModSecurity alerts
- Requests to known web-shell locations
- Attempts to retrieve application secrets or backup files

The detection system should support weighted classification rather than treating every suspicious-looking path identically.

---

## 8. Fail2ban Integration

Fail2ban is a useful alternative for standalone servers or as a fallback if Wazuh is temporarily unavailable.

It already has concepts for matching log events, banning addresses, performing custom actions, and automatically unbanning them.

Normally, a Fail2ban action creates a firewall block.

In our design, the custom action instead adds the IP to the tarpit quarantine controller.

The action should call the controller's supported add/remove interface rather than editing Apache files directly.

For example, conceptually:

```
actionban:
    adaptive-tarpit add <ip> --source fail2ban

actionunban:
    adaptive-tarpit release <ip> --source fail2ban
```

The final implementation must use safe argument handling, direct executable invocation where possible, and validated IP address input.

Avoid shell injection through untrusted address or alert data.

### Wazuh versus Fail2ban

Wazuh is preferred for centrally managed rules, richer security correlation, and fleet-level observability.

Fail2ban is attractive because it is simple and can operate independently on each server.

Support both, but ensure they use one common controller so they do not race to overwrite each other's decisions.

---

## 9. Detection Policy and Confidence

We need to be careful about false positives.

Not every suspicious-looking HTTP request is malicious.

For example:

- Some websites legitimately run WordPress.
- `/login` is commonly used by real applications.
- `/admin` can be a normal application endpoint.
- Security researchers may perform authorized scans.
- Monitoring systems can probe unusual URLs.
- Many legitimate users can share one public NAT address.
- University and corporate networks may place hundreds of users behind a single IP.
- An authenticated administrator may trigger unusual error patterns.

Therefore, a single request should generally not be enough to quarantine a source unless the evidence is exceptionally strong.

### Proposed scoring model

Treat these as initial policy candidates, not validated thresholds.

| Detection signal                                    | Suggested weight |
| --------------------------------------------------- | ---------------- |
| Isolated 404                                        | 0                |
| One generic `/login` request                        | 0                |
| Known sensitive-file probe, e.g. `/.env`            | 3                |
| Probe for `/.git/config`                            | 3                |
| Known exploit-specific URL                          | 5                |
| Multiple unrelated exploit families                 | +4               |
| Several distinct sensitive paths within 120 seconds | +4               |
| Repeated serious ModSecurity findings               | +5               |
| High-rate enumeration of nonexistent resources      | +2               |
| Authorized scanner, verified known source           | Exempt           |

A provisional policy might be:

- Score below 5: Observe only.
- Score 5-9: Elevated suspicion and additional logging.
- Score 10-14: Temporary tarpit classification.
- Score 15+: Stronger quarantine or blocking according to risk and rate.

The actual thresholds should be tuned against historical Apache access logs before enabling live enforcement.

### Additional safeguards

Do not classify solely by User-Agent.

User-Agent strings can be spoofed.

Do not treat raw `X-Forwarded-For` headers as authoritative.

Do not penalize a whole network range because one host behaved badly.

Do not automatically expand an IPv6 address to a `/64` or larger prefix.

Do not turn a path probe into a quarantine event if that path belongs to a legitimate local application unless other supporting evidence exists.

Use allowlists, protected-source lists, and explicit exception policies.

---

## 10. Quarantine State Machine

We should formalize the client's state.

Suggested states:

**NORMAL** — The IP is not currently classified as hostile. Its requests are handled normally.

**OBSERVED** — The IP has generated suspicious activity but has not reached the quarantine threshold. Continue monitoring.

**TARPITTED** — The IP has reached the confidence threshold. Subsequent requests are routed to the tarpit backend.

**BLOCKED** — The IP is consuming too many resources, exceeds concurrency limits, or triggers a higher-risk policy. Traffic is rejected or dropped rather than passed to the tarpit.

**EXPIRED** — The penalty has elapsed and the address returns to ordinary processing.

There can also be an administrative `ALLOWLISTED` state that overrides ordinary classifier decisions.

### Suggested escalation policy

Initial quarantine: 15 minutes.

Repeated confirmed scanning: 30 minutes.

Continued aggressive scanning: 60 minutes.

Extreme request volume or resource-abuse conditions: immediate drop.

These are starting values, not final decisions.

Each transition should have a machine-readable reason.

We should record whether the transition came from Wazuh, Fail2ban, an administrative command, or another source.

### Important distinction

Tarpitting is not always the correct response.

If a source creates thousands of simultaneous connections, actively maintaining those connections could harm us more than the scanner.

At that point, we should stop entertaining the scanner and drop or reject new traffic.

**Tarpit when resource economics favor us. Block when resource economics favor the attacker.**

That principle should guide the entire implementation.

---

## 11. Quarantine Controller

Create a small local controller that is independent from both Apache and the tarpit server.

Suggested command-line interface:

```
adaptive-tarpit add IP --ttl 900 --reason scanner
adaptive-tarpit release IP
adaptive-tarpit status IP
adaptive-tarpit list
adaptive-tarpit statistics
adaptive-tarpit allow IP
adaptive-tarpit disallow IP
adaptive-tarpit enable
adaptive-tarpit disable
adaptive-tarpit reconcile
adaptive-tarpit health
```

These commands describe desired behavior, not an existing implementation.

The precise API can change.

### Responsibilities

Store active quarantine entries; track expiration timestamps; enforce allowlist precedence; reject malformed addresses; prevent duplicate entries; maintain multiple active reasons or leases for one IP; generate the Apache routing map; expire entries; reconcile state following a restart; provide status information; log all classification changes; implement emergency shutdown or bypass; optionally maintain a firewall blocklist.

### Suggested state fields

```
ip
address_family
state
first_detected_at
last_detected_at
quarantine_started_at
expires_at
reason
source_detector
rule_id
confidence_score
event_count
protected_site
last_transition
```

Consider additional fields for active enforcement leases and extension history.

### Storage

SQLite would be reasonable for a single-host controller, provided concurrent writes are serialized and schema migrations are handled.

A simple JSON state file could also work for a very small deployment.

The Apache routing map should be a generated artifact, not the only authoritative state.

If the mapping file is lost or corrupted, the controller should reconstruct it.

### Operational requirements

Atomic state transitions; safe locking; bounded processing time; no untrusted shell evaluation; recovery from partial failures; predictable logging; idempotency; automatic expiration; no need for Apache reload on ordinary IP updates; strict permissions on control interfaces.

---

## 12. Tarpit Response Engine

The tarpit backend should be intentionally lightweight.

We want many slow client interactions without allocating one dedicated operating-system thread per connection.

A nonblocking event-driven server is preferred.

Node.js is a reasonable initial choice because the upstream reference implementation already supports it.

The backend should have no filesystem or network privileges beyond what it needs.

### 12.1 Response strategies

**Profile A: Slow fake configuration** — content resembling an application `.env` file, entirely fabricated, streamed in small chunks with significant delays.

**Profile B: Slow Git repository metadata** — plausible fake `.git/config` content. Do not expose real repository names or internal addresses.

**Profile C: Fake administrative website** — a convincing WordPress or generic application interface with links to additional fake pages. Encourage automated exploration without allowing actual application operations.

**Profile D: Slow error response** — a plausible HTTP error returned slowly. Useful for URLs that do not match a specific deception profile.

**Profile E: Slow JSON/API response** — syntactically valid but slowly streamed JSON. Useful against automated API scanners.

**Profile F: Delayed headers and progress** — experiment with intentional delays before response completion, regular streaming, and controlled pauses. Do not assume that sending a `Retry-After` header alone forces a scanner to wait; it is advisory and usually does not hold a connection open.

**Profile G: Controlled redirect maze** — optionally return same-origin links or redirects to additional decoy endpoints. Limit the number of redirects and avoid external destinations.

### 12.2 Slow-stream controls

```
min_chunk_bytes
max_chunk_bytes
min_chunk_delay_ms
max_chunk_delay_ms
max_response_duration_seconds
max_response_bytes
max_request_body_bytes
max_concurrent_connections
max_connections_per_ip
idle_timeout_seconds
```

All values should be configurable.

Every response must eventually complete or terminate.

No connection should remain open indefinitely.

### 12.3 Recommended initial response

Start by using the upstream `web-tarpit` slow `.env` response.

It is a simple, repeatable way to evaluate whether Apache forwards the stream as intended and whether scanners remain occupied.

Do not implement the entire deception catalog before validating the basic HTTP streaming and resource behavior.

### 12.4 HTTP methods

The backend must handle different methods deliberately.

For `HEAD`, use valid HTTP semantics and do not send a response body.

For `POST`, enforce request-body size limits and read deadlines.

For large uploads, do not permit an attacker to consume unlimited memory or disk space.

Handle aborted requests without unhandled exceptions.

Unsupported methods should receive a controlled response.

### 12.5 Fake credentials

Use only obviously nonfunctional synthetic credentials internally.

Never embed real keys, passwords, tokens, hostnames, or infrastructure details.

If optional credential-capture honeypot functionality is enabled, redact or hash sensitive values before logging and define an explicit retention policy.

The default should avoid retaining passwords entirely.

### 12.6 Security isolation

The backend must not execute commands received in HTTP requests.

It must not access production applications or databases.

It must not fetch arbitrary remote URLs supplied by attackers.

It must not become an open proxy.

It must not support attacker-controlled server-side callbacks.

Its responses should be generated entirely from local static content or bounded in-memory logic.

---

## 13. Resource Management: The Most Important Engineering Challenge

There is a fundamental difference between holding a scanner's connection open and doing so cheaply enough to be worthwhile.

A Node.js application can efficiently maintain many asynchronous connections.

However, if Apache is acting as the reverse proxy, every outstanding proxied request still consumes Apache-side connection and request-processing resources.

Using Node.js does not magically eliminate Apache's resource costs.

Apache's `mod_ratelimit` documentation explicitly warns that prolonged responses occupy a worker for their duration.

Proxying slow responses presents a related capacity concern.

We need to test the actual Apache MPM, request-handling behavior, and connection costs on the target systems.

### 13.1 Capacity modeling

```
Average concurrent requests
    ≈ request arrival rate × average request duration
```

If 20 requests per second are being tarpitted for an average of 60 seconds, we could accumulate approximately 1,200 concurrent requests.

That may be a perfectly reasonable load for one architecture and completely unacceptable for another.

The agent should measure actual concurrency behavior rather than relying on the theoretical scalability of Node.js alone.

### 13.2 Apache MPM considerations

Identify which MPM is in use: prefork, worker, event.

Determine the number of available request workers and how slow proxied responses affect them.

Do not assume the event MPM eliminates the worker-occupancy problem.

If the host uses prefork, a relatively small number of slow requests may be especially expensive.

### 13.3 Resource budgets

Design with explicit budgets for: Apache workers, backend connections, per-IP connections, file descriptors, memory, CPU, TCP socket buffers, total active slow responses, HTTP/2 streams, aggregate bandwidth, total delay budget.

The controller should have a configurable maximum amount of production capacity it is permitted to consume.

### 13.4 Overload behavior

When the available tarpit budget is exhausted, new offending requests should fail closed from the application's perspective.

They should not automatically reach the legitimate backend.

Acceptable overload behavior includes returning 429/403/503 or dropping traffic using an appropriate firewall mechanism.

The exact choice should be configurable.

Do not maintain thousands of additional slow connections just because the attacker requested them.

### 13.5 Failure isolation

A tarpit backend crash must not cause the legitimate website to fail.

The normal request path should remain independent.

A quarantined IP may receive a fast error if the tarpit is unavailable; that is acceptable.

It should not be silently forwarded to the protected application.

### 13.6 Critical benchmark question

**How many simultaneous slow responses can an Apache-backed deployment safely maintain before production request latency, worker availability, or error rate is affected?**

This must be measured under concurrent normal user traffic.

If the answer is unsatisfactory, we should consider the alternatives in the next section.

---

## 14. Alternative Architecture: nftables Redirect to a Dedicated Listener

We discussed removing HAProxy and potentially using the Linux firewall to divert classified IPs away from Apache altogether.

This is worth researching as a second-generation implementation.

### Concept

Wazuh identifies a scanner. The controller adds its IP address to an nftables set. For new connections from that IP, nftables changes the destination to a dedicated local tarpit listener. Apache is bypassed for those connections. This may be more attractive for protecting Apache worker capacity.

### Major complication: HTTPS

Redirecting TCP port 443 does not decrypt HTTPS traffic.

A separate HTTPS listener must correctly complete TLS negotiation for the requested hostname.

That introduces requirements for: valid certificates, certificate rotation, SNI handling, multiple virtual hosts, TLS protocol settings, ALPN negotiation, HTTP/2, and existing connection handling.

If Apache currently owns the certificates and TLS termination, redirecting encrypted connections to a separate process is more complex than proxying an already-decrypted request.

### Other complications

New versus established connections; conntrack behavior; IPv6 handling; local routing; firewalld integration; maintaining temporary sets; firewall reloads; multiple public IP addresses; same-host and remote traffic; HTTP/3/QUIC over UDP/443.

A TCP-only redirection does not capture QUIC traffic.

Also, a newly classified IP may continue using an existing HTTP/2 connection to Apache rather than opening a fresh TCP connection.

An Apache request-level decision may respond to classification changes on subsequent requests over that connection, depending on the implemented request-handling path.

A firewall NAT decision generally cannot retroactively move an established connection to a different process.

### Recommendation

Keep this as a researched alternative.

Do not select it as the first implementation unless the Apache resource tests demonstrate that request-level proxying is unsuitable.

However, it may ultimately provide stronger resource isolation.

Research whether a dedicated listener with TLS support, shared certificate access, or a purpose-built HTTP tarpit proxy can provide LaBrea-like economics more effectively than Apache reverse proxying.

---

## 15. Alternative Architecture: Apache-Only Tarpit

Potential tools include `mod_lua`, `mod_ratelimit`, ModSecurity response actions, and a purpose-built Apache module.

**mod_lua** — could potentially implement custom response generation and classification logic inside Apache. However, delaying responses inside Apache can still consume request workers. Lua code that sleeps while serving a request may be especially problematic. Any use of `mod_lua` must be evaluated against its security and concurrency behavior.

**mod_ratelimit** — can deliberately reduce response bandwidth. However, its configuration is expressed in KiB/s rather than arbitrary three-byte drip intervals. It is not a direct replacement for the `web-tarpit` streaming behavior. Apache explicitly warns that rate-limited responses occupy workers.

**ModSecurity** — may be useful as a detection source and, depending on the installed version, can support disruptive or delay-oriented actions. Do not assume an old ModSecurity action works in libModSecurity 3.

**Custom Apache module** — a purpose-built C module might be able to perform more efficient integration. But it also introduces considerable maintenance, testing, compatibility, and safety costs. We would need a compelling demonstrated advantage before selecting this path.

### Recommendation

Treat Apache-only implementations as exploratory.

The preferred first implementation remains Apache conditional routing to an isolated process.

---

## 16. SELinux and Oracle Linux Considerations

The target environment includes Oracle Linux 8/9 systems, and SELinux may be enforcing.

The implementation must preserve SELinux protections.

The agent should verify: Apache module availability, Apache version, installed MPM, current virtual-host configuration, relevant SELinux booleans, HTTP server network-connect permissions, tarpit service confinement, filesystem labels, firewall configuration, and existing Wazuh agent configuration.

Apache may require an appropriate SELinux policy allowance to proxy connections to a local backend.

Do not blindly disable SELinux.

Do not make broad permanent policy changes without first examining the actual denial and identifying the minimum necessary permission.

A dedicated systemd unit should run the backend as an unprivileged service account.

Use systemd sandboxing where practical.

The service should not need root privileges or access to production secrets.

Potential protections include:

```
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
```

The final unit must be compatible with the actual application.

The controller may require narrowly scoped privileged actions to update protected configuration files or firewall state.

Keep that privilege separate from the public-facing tarpit process.

---

## 17. Trusted Client IP Handling

This deserves explicit attention because incorrect source-IP handling could undermine the entire system.

If Apache receives connections directly from internet clients, the connection's remote address is generally the source we should classify.

If traffic passes through a trusted load balancer, CDN, or reverse proxy, the network peer may be the proxy rather than the originating client.

Apache supports `mod_remoteip` to derive the original client address from trusted proxy metadata.

However, arbitrary user-supplied `X-Forwarded-For` headers must not be trusted.

The agent should:

1. Identify the actual topology.
2. Determine whether Apache receives direct internet connections.
3. Identify any legitimate intermediate proxies.
4. Configure trusted proxy handling only where applicable.
5. Ensure Wazuh sees the same canonical client IP that Apache uses for classification.
6. Ensure the tarpit does not independently trust spoofable headers.
7. Test direct connections containing forged forwarding headers.

A serious failure would be allowing an attacker to send an arbitrary `X-Forwarded-For` value and cause another user or infrastructure address to be quarantined.

That must be prevented.

For multi-host deployments, the controller should also record which site or server observed the event rather than assuming every address should immediately be quarantined everywhere.

---

## 18. Safety, Allowlists, and Administrative Recovery

A system like this can cause real availability problems if it misclassifies traffic.

The project needs strong recovery mechanisms from the beginning.

### Mandatory exemptions

Support exemptions for: explicitly approved vulnerability scanners, monitoring infrastructure, internal trusted services, administrative management sources, health checks, known application integrations, and other approved operational traffic.

Do not rely only on reverse DNS or User-Agent strings to identify trusted scanners.

Where feasible, authorized scanner allowlists should be based on verified source ranges and tightly controlled configuration.

### Shared IP addresses

A university, employer, ISP, or residential network may have many users sharing a public address.

Automatically penalizing the whole source IP may affect unrelated legitimate users.

This is an unavoidable limitation of IP-level quarantine.

For that reason, require high-confidence detection and favor shorter penalties for addresses with uncertain attribution.

### Emergency bypass

There must be a simple administrative procedure to:

- Disable tarpit routing immediately
- Release all current quarantines
- Preserve logs for investigation
- Verify ordinary website operation
- Restart the controller cleanly
- Recover from a corrupted map

The emergency procedure must still work if Wazuh or the tarpit backend is unavailable.

### Logging hygiene

Do not log real secrets or full submitted passwords.

Treat request bodies, URL parameters, and attacker-supplied strings as untrusted.

Sanitize log fields and bound their lengths.

Avoid retaining sensitive payloads unless explicitly required for a security investigation.

Use appropriate retention policies.

---

## 19. Observability and Metrics

We do not need an elaborate dashboard for the first proof of concept, but we do need reliable event and performance data.

### Classification events

```
timestamp
server
virtual_host
source_ip
event_type
triggering_rule
reason
confidence_score
previous_state
new_state
quarantine_expiry
```

### Tarpit request events

```
timestamp
source_ip
requested_path
http_method
response_profile
response_status
duration_ms
bytes_sent
client_disconnected
timed_out
concurrency_at_start
```

Avoid storing secret-bearing request bodies.

### Operational metrics

Number of currently quarantined IPs; new quarantines per hour; expired quarantines; active tarpit requests; peak concurrent tarpit requests; mean and median tarpit response duration; aborted requests; bytes sent to tarpitted clients; backend memory and CPU usage; Apache busy workers; Apache request latency; normal-site 5xx error rate; tarpit backend errors; resource-budget rejections; manual false-positive releases.

### Effectiveness metrics

**Are we actually making scanners spend more time completing their work?**

Compare scanner behavior under: (1) normal quick 404 responses, (2) slow-drip responses, (3) fake application/decoy responses, (4) different configured timeout and chunk-delay profiles.

Observe whether the scanner: waits for completion, times out quickly, retries, opens more connections, abandons the target, changes scanning behavior, or follows decoy links.

Do not mistake a large count of open connections for successful defense if those connections also endanger production capacity.

---

## 20. Suggested Project Components

```
adaptive-web-tarpit/
|
+-- README.md
+-- ARCHITECTURE.md
+-- SECURITY.md
+-- THREAT-MODEL.md
+-- DEPLOYMENT.md
+-- OPERATIONS.md
|
+-- apache/
|   +-- adaptive-tarpit.conf
|   +-- example-vhost.conf
|   +-- README.md
|
+-- controller/
|   +-- quarantine-state
|   +-- map-generation
|   +-- expiration
|   +-- cli
|
+-- detector/
|   +-- wazuh/
|   |   +-- rules/
|   |   +-- active-response/
|   |
|   +-- fail2ban/
|       +-- filters/
|       +-- actions/
|
+-- tarpit/
|   +-- server/
|   +-- profiles/
|   +-- logging/
|   +-- limits/
|
+-- systemd/
|   +-- adaptive-tarpit.service
|   +-- adaptive-tarpit-expire.service
|   +-- adaptive-tarpit-expire.timer
|
+-- scripts/
|   +-- install.sh
|   +-- uninstall.sh
|   +-- validate.sh
|   +-- rollback.sh
|
+-- tests/
|   +-- unit/
|   +-- integration/
|   +-- security/
|   +-- load/
|
+-- examples/
|   +-- config.example
|
+-- docs/
    +-- oracle-linux.md
    +-- selinux.md
    +-- troubleshooting.md
```

The structure is illustrative.

Keep the implementation appropriately small.

Avoid introducing multiple daemons or unnecessary dependencies when one controller and one backend process are sufficient.

---

## 21. Implementation Roadmap

**Phase 0: Environment and feasibility assessment** — inspect the target Apache deployment; determine the MPM; identify all relevant virtual hosts; inspect current rewrite and proxy configuration; determine whether traffic arrives directly or through a proxy; identify the Apache log format; check Wazuh availability and current rules; check SELinux and firewalld; verify installed Node.js compatibility; verify that the reference project works on the host. Deliver an architecture feasibility report. Do not assume a standalone test Apache configuration will translate directly to production.

**Phase 1: Standalone tarpit proof of concept** — build the local tarpit backend: listen only on loopback; produce genuine slow HTTP responses; reuse upstream `web-tarpit` where appropriate; handle disconnects; enforce request limits; produce structured logs; run as an unprivileged service; provide a health-check mechanism that does not itself generate a prolonged response. Verify using `curl` and a small local test client that measures first-byte time, total duration, and chunk arrival.

**Phase 2: Apache routing proof of concept** — configure Apache to route a manually specified test IP to the tarpit. Do not integrate Wazuh yet. Verify: normal IP sees the real website; flagged IP sees the tarpit; existing virtual hosts still work; HTTPS remains valid; HTTP/2 works; the tarpit stream reaches the client; removing the IP restores normal routing; no Apache restart is needed for membership changes. This phase is the first major feasibility gate.

**Phase 3: Quarantine controller** — implement persistent classification state and the Apache map generator. Add CLI, expiration, multiple active leases, atomic writes, manual overrides, recovery after restart, structured event logging, emergency bypass. Test all controller functionality before attaching automatic detector actions.

**Phase 4: Wazuh integration** — build a custom Active Response integration. Start with a dedicated test rule or explicit controlled event. Verify the complete path: test alert -> Wazuh action -> controller -> Apache map update -> request routed to tarpit -> expiration -> normal routing restored. Then introduce real detection rules. Use observe-only mode initially to collect candidate classifications and identify likely false positives.

**Phase 5: Fail2ban adapter** — implement an optional Fail2ban action that uses the same controller. Test independent add/remove operations and overlapping Wazuh classifications.

**Phase 6: Resource protection** — introduce or validate: global concurrency ceiling, per-IP concurrency ceiling, backend overload handling, connection lifetime limits, memory limits, file descriptor limits, Apache worker budget, firewall fallback, automatic recovery from backend failure. Do not proceed to broad deployment until this phase demonstrates acceptable behavior.

**Phase 7: Enhanced deception** — after the basic design proves effective: different trap profiles, fake application navigation, more intelligent response selection, fake vulnerable service identities, configurable deception per virtual host, better logging and analysis, optional XML-RPC honeypot behavior, correlation of repeated scanner behavior. Deception must remain static or otherwise tightly controlled. Do not give the backend general-purpose access to the production network.

**Phase 8: Alternative transport research** — benchmark the Apache proxy approach against firewall redirection to a dedicated listener. Determine whether a more efficient transport architecture would substantially improve simultaneous connection capacity. Only pursue additional architectural complexity if measurements justify it.

---

## 22. Testing Requirements

### Functional tests

Non-quarantined IPv4 clients reach production; non-quarantined IPv6 clients reach production; quarantined IPv4 clients enter the tarpit; quarantined IPv6 clients enter the tarpit; arbitrary URLs from quarantined clients are intercepted; requests using ordinary URLs do not bypass quarantine; quarantine expiration restores ordinary processing; repeated detections correctly extend quarantine; multiple detector leases do not conflict; allowlists override ordinary classification; explicit release works; controller restart preserves state; Apache restart restores correct classification; tarpit backend restart recovers cleanly; failed map updates do not corrupt configuration.

### Security tests

Forged `X-Forwarded-For`; forged `CF-Connecting-IP`; malformed IPv4; malformed IPv6; invalid CIDR entries; log injection; shell metacharacters; oversized request headers; oversized request bodies; HTTP request smuggling-related edge cases; unexpected URL encodings; invalid HTTP methods; Host header injection; upstream proxy confusion; attempts to reach internal services through proxy routing.

### Performance tests

Measure under normal application load while increasing tarpit concurrency. Track Apache request latency, Apache worker utilization, production application error rate, Node.js memory, CPU, open file descriptors, active TCP connections, HTTP/2 stream behavior, backend timeouts. The system must preserve legitimate service availability even when the tarpit is under heavy load.

### Scanner behavior tests

Use authorized scanners against a dedicated test target, never an unrelated external system. Compare scan completion times against a control server returning ordinary immediate errors. Test scanners with different timeout and concurrency configurations. Determine whether the slow-response mechanism actually causes useful delays.

### Recovery tests

Simulate: Wazuh stopping; controller stopping; backend crashing; Apache reloading; host rebooting; mapping file corruption; quarantine database corruption; simultaneous updates; firewall reload; SELinux denial; log filesystem exhaustion. Every failure should have documented, predictable consequences.

---

## 23. Acceptance Criteria

**Routing correctness** — Normal traffic reaches the existing production website unchanged. A flagged IP is intercepted, and its subsequent requests are handled by the tarpit.

**Dynamic behavior** — Classification changes take effect without restarting Apache.

**Automatic expiration** — Temporary quarantines expire reliably, including across restarts and overlapping detections.

**Detection integration** — A Wazuh alert can trigger the full workflow without manual intervention.

**Security** — Spoofed forwarding headers cannot cause arbitrary third-party addresses to be quarantined.

**Isolation** — The tarpit has no privileged access to production applications or secrets.

**Resource protection** — There is an enforced and tested maximum consumption budget.

**Operational recovery** — An administrator can disable the system and restore normal processing promptly.

**Observability** — The system records why each address was classified and how its HTTP interactions were handled.

**Demonstrable effectiveness** — Controlled scanner tests show whether the tarpit creates additional scanner delay compared with ordinary fast responses.

If the system cannot demonstrate meaningful delays without significant production cost, we should reevaluate the architecture rather than deploy an ineffective countermeasure.

---

## 24. Initial Configuration Defaults to Investigate

Proposed starting values for testing, not validated production defaults.

| Setting                        | Initial candidate                                        |
| ------------------------------ | -------------------------------------------------------- |
| Initial quarantine             | 15 minutes                                               |
| Repeat quarantine              | 30 minutes                                               |
| Maximum ordinary quarantine    | 60 minutes                                               |
| Typical chunk size             | 3 bytes                                                  |
| Random chunk delay             | 100-500 ms                                               |
| Maximum slow response duration | 120 seconds                                              |
| Local tarpit listener          | 127.0.0.1:3001                                           |
| XML-RPC mode                   | Fault only                                               |
| Credential capture             | Disabled                                                 |
| Detection behavior             | Observe first, then enforce                              |
| Apache map update              | Atomic replacement                                       |
| Backend failure behavior       | Fast error or reject, never production fallthrough       |
| Excessive tarpit concurrency   | Reject/drop instead of creating more long-lived requests |
| Initial deployment             | One noncritical Apache host                              |

Actual concurrency ceilings and body-size limits must be chosen after measuring host capacity.

Do not select a global tarpit connection limit solely from theoretical Node.js scalability. Apache will often be the more important limiting factor.

---

## 25. Questions the Implementing Agent Must Resolve

**Apache**

1. Can the chosen RewriteMap and proxy configuration reliably intercept all requests from classified IPs across the current virtual hosts?
2. Does map caching reliably detect rapid updates without a reload?
3. How does the implementation behave with existing `.htaccess` files and application rewrites?
4. How much Apache request-worker capacity is consumed per slow proxied response?
5. Does Apache forward streaming chunks promptly?
6. Which timeout settings affect long-lived responses?
7. Can we impose practical global/per-source resource ceilings before entering the proxy path?
8. Does HTTP/2 multiplexing materially change resource consumption or routing behavior?

**Tarpit backend**

9. How many concurrent response streams can the standalone backend maintain?
10. What happens when the remote scanner disconnects?
11. Does upstream `web-tarpit` correctly cancel all scheduled streaming work?
12. Can we support arbitrary quarantined URLs without forcing every request to a fixed fake path?
13. Is a wrapper sufficient, or should we fork the upstream library?
14. Which deception responses keep real scanners engaged longest?
15. Which clients simply timeout or abandon the connection?

**Detection**

16. Which existing Wazuh rules already identify web vulnerability scans?
17. Are Apache source IPs represented correctly in Wazuh alerts?
18. Would ModSecurity provide better high-confidence detection?
19. What are the false-positive risks for our real application URLs?
20. Should quarantine state be shared across servers or remain local initially?
21. How should repeated alerts extend or escalate penalties?

**Linux networking**

22. Could nftables connection redirection provide significantly better isolation?
23. What is the simplest correct way to terminate HTTPS in that architecture?
24. Can an isolated listener handle all required hostnames and certificates?
25. Would HTTP/3/QUIC bypass the selected enforcement approach?

**Operations**

26. How should the system behave if the quarantine controller fails?
27. What is the safest default if the backend fails?
28. How do we preserve quarantine state after reboot?
29. How do we prevent a false positive from affecting a large shared NAT population?
30. How can we measure actual scanner time wasted without overstating effectiveness?

---

## 26. Engineering Expectations

Prefer: small components, explicit interfaces, minimal dependencies, clear separation of privileges, idempotent administration, structured logs, deterministic tests, reproducible installations, independent rollback, safe default settings, version-pinned dependencies, complete documentation.

For Bash installation and maintenance scripts: use `set -euo pipefail`; emit timestamped logs; validate all inputs; use traps to report errors; avoid unnecessary service restarts; test configuration before reloading services; make repeated execution safe; preserve existing configuration; provide complete uninstall and rollback procedures.

For generated Apache configuration: validate with `httpd -t`; check loaded modules; avoid conflicting rewrite rules; document exactly where configuration is installed; preserve existing virtual-host behavior.

For changes involving SELinux or firewalld: inspect current state; apply the narrowest necessary changes; document them; make them reversible; do not disable protections globally just to make the prototype work.

For development: provide unit tests for classification and expiry; provide integration tests for Apache routing; include load and failure tests; never claim performance characteristics that have not been measured.

---

## 27. Priorities and Explicit Non-Goals

### Highest priorities

1. Reliable identification of hostile scanning behavior.
2. Automatic temporary per-IP quarantine.
3. Apache integration without HAProxy.
4. Effective slow-response generation.
5. Minimal impact on legitimate requests.
6. Hard resource isolation and overload protection.
7. Automatic expiration and recovery.
8. Logging sufficient to measure effectiveness.

### Secondary priorities

Multiple deception profiles; better scanner classification; Wazuh rule refinement; cross-host correlation; dashboards; optimized firewall redirection; support for additional web servers.

### Not initial goals

Replacing Apache; building a full WAF; building an intrusion-prevention suite from scratch; permanent blacklisting of every suspicious address; automatically retaliating against scanners; exploiting remote systems; capturing genuine credentials; complex distributed orchestration; deploying a new centralized HTTP gateway; modifying individual production web applications; building a completely new Apache module before proving the concept.

Scope should remain focused.

---

## 28. Recommended Immediate Work for the Agent

Begin by independently validating the architecture against the actual upstream source code and Apache documentation.

Then implement a minimal end-to-end proof of concept using:

```
Apache 2.4
    |
    | dynamic RewriteMap lookup
    |
    +-- normal IP --> existing website
    |
    +-- quarantined IP
            |
            v
       mod_proxy
            |
            v
       127.0.0.1:3001
            |
            v
       web-tarpit wrapper
            |
            v
       slow HTTP response
```

The first milestone should demonstrate that adding and removing one test IP dynamically changes routing without an Apache restart and without touching the legitimate site's application code.

The second milestone should establish the resource cost of maintaining slow connections through Apache.

The third milestone should connect Wazuh and automatic expiration.

Do not spend time building sophisticated decoy pages or dashboards until these three fundamentals are proven.

If Apache's worker economics make the approach unsafe, present measured evidence and compare alternatives rather than blindly expanding the original architecture.

**Owner addendum:** benchmark two implementations early — Apache reverse-proxy tarpitting versus direct firewall redirection to an isolated listener. The first is much easier to integrate. The second may be closer to LaBrea's original resource-efficiency philosophy. That decision must come from actual Apache worker and connection measurements, not assumptions.

---

## 29. Reference Documentation

- LaBrea TCP tarpit — original inspiration
- https://github.com/crumrine/web-tarpit (+ `src/tarpit.js`, `src/adapters.js`)
- https://httpd.apache.org/docs/2.4/rewrite/rewritemap.html
- https://httpd.apache.org/docs/2.4/rewrite/flags.html
- https://httpd.apache.org/docs/2.4/howto/reverse_proxy.html
- https://httpd.apache.org/docs/2.4/mod/mod_proxy.html
- https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html
- https://httpd.apache.org/docs/2.4/mod/mod_ratelimit.html
- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/
- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
- https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts

---

## 30. Final Architectural Direction

The intent of this project is not simply to serve fake WordPress pages.

It is to create an automated, resource-conscious defensive system that changes how our web infrastructure responds to confidently identified automated abuse.

Today, vulnerability scanners generally benefit from fast, predictable answers.

Our proposed system should selectively remove that advantage.

A source that behaves like a legitimate visitor continues to receive normal service.

A source that clearly behaves like a vulnerability scanner can instead encounter an intentionally slow, deceptive environment.

The system should make automated scanning more expensive in elapsed time and opportunity cost, without making the real website less reliable.

**Wazuh for detection. Apache for request-level classification and routing. A dedicated lightweight process for deception and deliberately slow responses. A small quarantine controller for state, expiration, and operational control. Firewall-based rejection when continued tarpitting would become expensive or unsafe.**

**Success is not how long we can keep one TCP connection open. Success is how much verified scanner time we can consume per unit of defender resources, while preserving the availability and integrity of the actual websites.**
