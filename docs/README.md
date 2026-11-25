# Documentation

Everything here is about running Fleet Filter. Design records and development handoffs are not
published - they answer questions about how the system was arrived at, which is not the same question
as how to operate it.

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
- A document that describes behaviour the code does not have is worse than no document. Where
  something is planned rather than built, it says so.
