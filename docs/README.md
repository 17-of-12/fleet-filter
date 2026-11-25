# Documentation

These documents cover running Fleet Filter: deploying it behind your own certificate or load
balancer, distributing signed policy to hosts, responding to a quarantined source, and judging what
the project has actually been shown to stop.

## Deploying

| step | document |
|---|---|
| understand the three deployment shapes | [../deploy/topologies/README.md](../deploy/topologies/README.md) |
| TLS, certificates and renewal | [../deploy/topologies/README-tls.md](../deploy/topologies/README-tls.md) and [operations/CERTIFICATES.md](operations/CERTIFICATES.md) |
| render a policy for a host and get it onto the host | [operations/POLICY-DISTRIBUTION.md](operations/POLICY-DISTRIBUTION.md) |
| respond to a quarantined source, and for how long | [operations/LADDER.md](operations/LADDER.md) |
| author a signature the gateway can enforce | [spec/DETECTION-INPUTS.md](spec/DETECTION-INPUTS.md) |
| implement a responder behind the gateway | [spec/responder-interface.md](spec/responder-interface.md) |

## Judging it

| question | document |
|---|---|
| what is actually proven to stop attacks? | [EXPLOIT-CORPUS.md](EXPLOIT-CORPUS.md) - the scoreboard, including what is unverified |
| where does vulnerability data come from and under what licence? | [DATA-SOURCES.md](DATA-SOURCES.md) |

## Contributing

| question | document |
|---|---|
| how do I contribute an exploit, and what evidence is required? | [EXPLOIT-CORPUS.md](EXPLOIT-CORPUS.md#contributing-a-new-exploit-back) |
| stand up a victim to test against | [../lab/README.md](../lab/README.md) |
| how do contributions reach this repository? | [../CONTRIBUTING.md](../CONTRIBUTING.md) |
| how do I report a vulnerability privately? | [../SECURITY.md](../SECURITY.md) |

## Conventions

- Every relative link is checked by `bin/check-doc-links.py`, which runs inside `bin/check.sh --all`,
  so a moved file that leaves a stale reference fails the build.
- A document records what the code does today. Work not yet built is listed once in
  [ROADMAP.md](../ROADMAP.md), not promised inside a reference page.
