# Contributing

The most valuable contribution to this project is **evidence**, not code. A new signature is easy to
write and hard to justify; a recorded run showing an attack working without the control and failing
through it is what makes the signature worth shipping.

## The single most useful contribution

A corpus entry: a vulnerability that affects web-facing software, reproduced against a victim you
are authorised to attack, with the request shape extracted and a benign request recorded next to it.
The process is written down in
[`docs/EXPLOIT-CORPUS.md`](docs/EXPLOIT-CORPUS.md#contributing-a-new-exploit-back) and checked by
`bin/exploit-upstream.py`, which refuses an entry whose signature, verdict or evidence is missing.

## How this repository takes contributions

**This public repository is a derived tree.** It is produced by `bin/export-public.py` from the
maintainers' working repository, which also holds estate-specific material that must not be
published: host inventories, harvested configuration, lab addresses. That has one consequence you
should know before you spend an evening on a patch:

- Issues and security reports are read here.
- Pull requests are welcome and are reviewed here, but a merge cannot land directly on `main`:
  the change is applied to the private tree and appears in the next export, with your authorship
  recorded in the commit trailer (`Co-authored-by:`).
- If a PR cannot be carried across (it depends on something only in the private tree), you will be
  told why rather than left waiting.

This is a deliberate trade to keep one source of truth. If it becomes a problem, say so in an issue —
that is exactly the kind of feedback that should change a process.

## What a good change looks like

- **Scoped.** One exploit, one defect, one behaviour. A pull request that adds a signature and also
  refactors the matcher cannot be reviewed for either.
- **Tested where it can be.** Rust changes need a test that fails before the fix; signature entries
  need positive and negative fixtures; scripts need a unit test. `bin/check.sh --all` is the gate,
  and it is what CI runs.
- **Honest about coverage.** If the rule matches a shape but the exploit was never observed working
  on a victim, the entry stays `unverified`. The ledger has a word for every state of knowledge;
  using the wrong one is worse than filing nothing.
- **Explained.** Commit messages say why, not what. The diff already says what.

## Conventions

- **Commit messages** follow [Conventional Commits](https://www.conventionalcommits.org/):
  `type(scope): summary`, where type is `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`
  or `security`. The body explains the reasoning and names what was measured.
- **One logical change per commit.** Squash noise before you open the PR.
- **No generated artifacts in a commit** unless the repository tracks them deliberately
  (the rendered topology policies are tracked; build output is not).
- **Do not reformat unrelated files.** A whitespace-only diff hides the change that matters.
- **Sign-off is not required**, but if your employer claims the work, tell us so it can be licensed
  consistently with the MIT license.

## Reporting a vulnerability

Not here. See [`SECURITY.md`](SECURITY.md) - private reporting only. A public issue describing a
bypass teaches attackers before anyone can patch it.

## Development environment

```bash
git clone https://github.com/17-of-12/fleet-filter.git
cd fleet-filter
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -r requirements-dev.txt
(cd gateway && cargo build --release)
./bin/check.sh --all
```

`bin/check.sh --all` runs rustfmt, clippy, the Rust tests, the Python suites on every available
interpreter, the signature-store checks, the exploit ledger and the upstream-contribution check.
If it passes locally, CI should agree.

## Code of conduct

Participation is covered by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
