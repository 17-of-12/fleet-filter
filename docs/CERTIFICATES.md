# Certificates

The gateway terminates TLS, so it holds the site certificate and owns its renewal. In the deployed
estate most certificates live on the F5 instead; that is a different topology with different
consequences, covered at the end. This document is for the case where the gateway is the endpoint.

Verified position, 2026-11-24: the deployed lab-web01 listener presents an InCommon RSA Server CA 2
certificate for `CN=lab-web01.lab` valid to **2026-02-28**, and nothing in the repo watched
that date.

## The three pieces

| piece | path | job |
|---|---|---|
| acquisition | `certbot certonly` (one-time) | prove control of the name once |
| renewal | `fleet-filter-gateway-cert.{service,timer}` | daily `certbot renew`, no-op unless due |
| handover | `bin/gateway-cert-deploy.sh` | validate, install, reload, **verify what is served** |

The handover is the part that fails quietly, which is why it is a separate, testable script rather
than a line in a hook.

### What the handover checks, and why

1. **Key matches certificate** before installing. Installing a mismatched pair takes the listener
   from "old certificate" to "no working listener"; the old certificate is the better failure.
2. **Not expiring inside the window** (default 7 days). `certbot renew` only calls the hook on
   success, so a certificate that is still short-dated means something upstream is wrong.
3. **Covers the expected host**, when `--expect-host` is given. A renewal for the wrong name is
   otherwise indistinguishable from a renewal for the right one.
4. **Atomic install.** A temporary file in the destination directory, then `rename`, so the gateway
   reads either the old file or the new one.
5. **Ownership to the service account.** Measured on lab-web01: a `0600` key owned by root is *not*
   readable by a service running as `fleet-filter-gw`, and the gateway loads TLS before binding, so
   that mistake is a failed start rather than a silent downgrade.
6. **Reload, then read the served certificate back** and compare its SHA-256 fingerprint with the one
   just installed. A reload that logs success while serving the old certificate is a real failure
   mode: on 2026-11-24 the reload compared policy digests, which do not include certificate bytes, so
   a renewed file in place was reported as `policy reload: unchanged` and the old certificate stayed
   in service. That comparison is fixed; this check is what proves it stays fixed.
7. **Rollback on failed verification.** The previous files are restored and reloaded, so a failed
   attempt leaves the listener exactly as it was.

## Challenge modes

Acquisition is per-host and depends on what can answer for the name.

**HTTP-01, standalone** — simplest when the host owns port 80 and nothing else does:

```
certbot certonly --standalone -d gateway.example.edu --deploy-hook /usr/local/sbin/fleet-filter-cert-deploy
```

**HTTP-01, webroot** — when port 80 is served by Apache or forwarded by the F5:

```
certbot certonly --webroot -w /var/www/html -d gateway.example.edu
```

The F5 must forward `/.well-known/acme-challenge/` to this member, or the challenge is answered by
whatever the F5 does with unknown paths.

**DNS-01** — needed for wildcards, and avoids inbound port 80 entirely. Against Technitium (which
the estate already runs) there are three working routes, verified 2026-11-24:

* `certbot-dns-technitium` (PyPI, v0.1.2, third party, small) — direct API integration;
* `certbot-dns-rfc2136` (official) — Technitium supports RFC 2136 dynamic updates;
* `lego --dns exec` with a script that calls the Technitium record API — no Python plugin needed, and
  `acme.sh` has a `dns_technitium` provider if shell is preferred.

A wildcard certificate is the one case where the single-certificate-per-listener limitation below
stops mattering for name coverage, though it does not add SNI selection.

## Limitations worth knowing before promising anything

* **One certificate per listener.** There is no SNI-based selection and no client-certificate
  (mTLS) verification in the gateway. Multiple vhosts need multiple listeners or one certificate
  with several SANs.
* **The private key lives on the gateway host.** It is owned by the service account, mode 0600, and
  that host is secret-bearing from then on.
* **Renewal is not monitored by the gateway.** `bin/gateway-cert-status.sh` reports days remaining
  and exits non-zero inside a window (default 21 days); it is meant to run from the existing
  monitoring, not from the proxy. `--json` emits `days_remaining` for whatever alerting exists.
* **Certificate material is reloaded, policy is reloaded.** Both happen on SIGHUP, atomically:
  connections already accepted keep the material they were accepted with, new connections get the
  new one.

## When the F5 terminates instead

If the F5 holds the certificate and speaks plaintext to the pool, none of the above applies: the
gateway needs no certificate, and `[listener] trusted_proxies` is what makes the client address
meaningful. Two consequences:

* There is no TLS visibility at the gateway at all - no ALPN, no SNI, no version. Those facts live on
  the F5.
* If the virtual server speaks HTTP/1.1 to the pool, the gateway never sees HTTP/2 and the h2
  protocol shapes cannot fire in production. That surface belongs to the F5.

Everything in this document is for the gateway-as-endpoint case, which is also the case the lab
proves.

## What was measured, not assumed (2026-11-24)

Run against a live lab listener, not a stub:

```
before: CN=first.example
mismatched key        refused, nothing replaced
1-day certificate     refused (inside the 7d window)
valid renewal         installed, reloaded, listener verified at the new fingerprint
after:  CN=second.example
failed verification   installed, verified against a dead listener, rolled back,
                      file back to CN=second.example, listener still serving it
```

The failed-verification run is the important one: the hook had already installed the new files and
had already signalled the reload. It still put the old certificate back, so a renewal that cannot be
proven in service leaves the listener exactly as it was.

`bin/gateway-cert-status.sh` reports days remaining (59 in that run) and exits non-zero inside a
window, which is the check that would have caught the 2026-02-28 expiry sitting unmonitored.
