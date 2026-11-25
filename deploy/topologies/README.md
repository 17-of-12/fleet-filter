# Deployment topologies

Three shapes, each rendered by `bin/render-topology.py` into a complete, parser-validated policy.
Pick the one that describes where TLS ends, because that single fact decides what the gateway can
see and what it must be told.

| topology | TLS ends at | gateway sees | client address from | h2 shapes |
|---|---|---|---|---|
| `edge-tls` | gateway | plaintext | the connection | fire |
| `behind-lb-plain` | load balancer | plaintext h1.1 from the LB | `X-Forwarded-For`, trusted only from the LB | never fire |
| `behind-lb-tls` | load balancer, then re-encrypted | plaintext | `X-Forwarded-For`, trusted only from the LB | fire when the LB negotiates h2 to the pool |

## Render one

```
bin/render-topology.py --list

bin/render-topology.py --topology behind-lb-plain \
  --host origin.example.edu \
  --backend http://127.0.0.1:8080 \
  --trusted-proxy 10.0.0.0/8 \
  --trusted-proxy 10.30.0.0/16 \
  --out /etc/fleet-filter/policy.toml
```

The renderer refuses contradictory inputs rather than producing a policy that parses and then
behaves as something other than its name: a certificate on a profile that terminates nothing, a
trusted proxy on the edge profile, or a load balancer profile with no proxy to trust.

## Why the files are generated, not hand-written

The `[detection]` table comes from `controller/signatures/signatures.yaml`. A hand-copied example
goes stale the first time a signature is added, and a stale example is worse than no example
because it looks authoritative. `tests/unit/test_topologies.py` re-renders each shipped file and
fails on any difference outside the timestamps, so the committed files cannot drift.

## What every profile still does not do

* No WebSocket upgrade - `Connection` and `Upgrade` are hop-by-hop and stripped, so a WebSocket
  handshake will not traverse the gateway.
* No HTTP/3.
* No SNI-based certificate selection and no client-certificate (mTLS) verification. One certificate
  per listener.
* The upstream leg is plaintext: `default_backend` must be `http://`. If the origin needs TLS, that
  belongs at the balancer or in a future backend-TLS option, not in an example that pretends.

## Install steps the policy does not do for you

A rendered policy names paths; it does not create them. On a fresh host:

```
install -d -m 0750 -o fleet-filter -g fleet-filter /var/lib/fleet-filter/spool
install -d -m 0755 /etc/fleet-filter
install -m 0644 policy.toml /etc/fleet-filter/policy.toml
```

If the spool directory is missing, the gateway still serves and still detects - it logs
`spool=failed` on each detection and loses the claim, so the quarantine does not survive a restart.
That is a degradation, not an outage, and it is invisible unless someone reads the journal: the
2026-11-24 smoke test of `behind-lb-plain` ran exactly that way on a host with no spool directory,
which is why the check is written down here.

The certificate profiles also need `/etc/fleet-filter/tls/` and the material the policy names; see
`README-tls.md`.
