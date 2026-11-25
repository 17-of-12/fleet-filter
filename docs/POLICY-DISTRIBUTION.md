# Policy distribution: pull, verified, reversible

One control node renders a policy per host; each host pulls its own file, validates it, applies it,
and proves the gateway took it. Nothing is pushed.

## Why pull

The hosts that matter cannot be dialled: one sits behind a load balancer, others are on management
networks with no inbound path from the control node. Outbound SSH is the direction that always
exists, so a host that fetches its own file works everywhere. It also means a compromised control
node can publish a bad policy but cannot make a host skip validation - the parser runs on the host,
against the bytes that host is about to run.

## The two commands

Control node:

```bash
bin/publish-policies.py --out /var/lib/fleet-filter/publish
```

Reads `config/hosts.yaml`, renders each host's policy through `bin/render-topology.py`, **validates
it with the gateway's own parser**, and writes `<host>.toml` plus `<host>.sha256` and a
`manifest.json`. A host removed from the table stops being published, so the directory cannot
accumulate stale policies that look current to whoever fetches next.

Host:

```bash
bin/policy-fetch.sh --source root@control:/var/lib/fleet-filter/publish \
                    --name ff-apache01 --dest /etc/fleet-filter/policy.toml --unit fleet-filter-gateway
```

1. Fetches the policy and its digest; refuses a mismatch (a truncated file must not be applied).
2. Runs `fleet-filter-gateway --policy <temp> --show-policy`. The parser is the authority; a policy
   it refuses would be a restart loop on a host with no console.
3. No-ops when the digest already matches, so a ten-minute timer costs one SSH round trip.
4. Installs atomically (`install -m 0644` from a temp copy), sends SIGHUP, then **waits for the
   journal** to say `policy reload ok` against the new digest. A signal is not proof.
5. On any failure, restores the previous policy, reloads again, and exits non-zero.

## Measured 2026-11-25

| step | result |
|---|---|
| publish two hosts | both validated by the binary, digests written |
| fetch v2 over a running gateway | installed, `policy reload ok` confirmed from the log, live file now v2 |
| fetch again | `already current`, no reload |

## Notes

* `--pid`/`--log` exist for hosts without systemd (containers, lab processes). The journal check
  reads the process log instead; the evidence is the same line.
* The gateway swaps policy atomically: connections already accepted keep the policy they were
  accepted under, new ones get the new file. That is what makes a ten-minute timer safe.
* `config/hosts.yaml` carries the per-host topology and its arguments, so the shape of each
  deployment is written once rather than per host.

## Signing (why the digest alone is not enough)

The digest and the policy come from the same host. On its own the digest proves the transfer was
intact; it says nothing about who wrote the file, so a compromised or spoofed control node serves a
policy and the hash that blesses it.

The publisher signs each digest with an RSA key (`--signing-key`), and the host verifies that
signature against a public key it was given **out of band, at provisioning time**
(`/etc/fleet-filter/policy-signing.pub`). The host recomputes the digest itself and verifies the
signature over the value it computed, so swapping the policy fails twice.

```bash
# control node, once
openssl genrsa -out /etc/fleet-filter/policy-signing.key 3072
openssl rsa -in /etc/fleet-filter/policy-signing.key -pubout \
    -out /etc/fleet-filter/policy-signing.pub
# every host, once, by an operator (not over the channel being trusted)
install -m 0644 policy-signing.pub /etc/fleet-filter/policy-signing.pub

# publish
bin/publish-policies.py --out /srv/policies --signing-key /etc/fleet-filter/policy-signing.key
```

Measured 2026-11-25: a validly signed bundle installed and the reload was confirmed from the log; a
tampered digest failed with `the digest is not signed by the policy signing key`; a host with no
key, and no `--allow-unsigned`, refused to install at all.

Residual: the private key sits on the control node, so compromise of that host still lets an
attacker sign. Signing moves the trust from "anything that can write the directory" to "whoever
holds this key" - a smaller set, not an empty one.
