# Security Policy

Fleet Filter is a security control, so a flaw in it is worth more to an attacker than a flaw in an
ordinary service. Please report privately and give us a chance to fix it before it is public.

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

Use GitHub's private reporting: the **Report a vulnerability** button under the
[Security tab](https://github.com/17-of-12/fleet-filter/security/advisories/new). That opens a
private advisory visible only to you and the maintainers.

Please include, as far as you can:

- the affected component (gateway, controller, responder, tooling) and version or commit
- what an attacker gains, and what they need in front of them to get it
- a request, config or script that reproduces it
- whether it needs the gateway to be reachable, and over which protocol

If you are unsure whether something is a vulnerability, report it anyway. A bypass that only works
under an unusual deployment is still a bypass.

## What to expect

| stage | target |
|---|---|
| acknowledgement | 3 working days |
| initial assessment (is it a vulnerability, how severe) | 10 working days |
| fix or documented mitigation | depends on severity; you will be told the plan |

We will credit you in the advisory unless you ask us not to. We will not take legal action against
research done in good faith against your own deployment.

## In scope

- bypasses of the gateway's detection or enforcement, including encoding tricks, protocol
  differences and header handling
- ways to make the gateway forward a request it should have answered, or answer one it should
  have forwarded
- denial of service against the gateway itself (memory, connections, parsing)
- flaws in policy distribution, signing, verification or reload
- weaknesses in the deception responder, including ways to make it amplify an attacker's effect
- the console, where a lower-privileged user can reach a higher-privileged action

## Out of scope

- attacks against an origin that is reachable **without** passing the gateway. That is a deployment
  error, and the documentation says so; the evidence ledger also states that every control claim
  assumes traffic takes the proxy path.
- anything requiring an operator to run attacker-supplied commands, or to deploy a policy an
  attacker wrote
- missing hardening headers on pages whose only purpose is to deceive a scanner
- results from a scanner with no demonstrated effect. "A rule did not match" is a coverage gap,
  not a vulnerability - open an issue for that instead, or better, a corpus contribution.

## Known limits we already document

These are recorded deliberately in [`docs/EXPLOIT-CORPUS.md`](docs/EXPLOIT-CORPUS.md) and are not
vulnerabilities by themselves:

- the gateway does not inspect response bodies
- body inspection is a literal marker search, bounded by a size cap
- HTTP/2 frames are parsed by the library, not visible to detection
- there is no WebSocket upgrade support and no HTTP/3
- a scanner that never reads responses is not delayed by deception
