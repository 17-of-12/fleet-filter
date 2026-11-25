# Repository settings that cannot be applied by the bot

The GitHub App (`Pragma-17of12`) holds `contents`, `workflows`, `actions`, `checks`, `statuses`,
`issues`, `pull_requests` and `discussions` at write, and `metadata` at read. It does **not** hold
`administration` or any organisation permission, so a whole class of settings is browser-only. This
file records them, their intended values, and why they are not automated - so the gap is explicit
rather than a thing someone remembers.

## Branch protection for `main`

Settings -> Branches -> Add branch protection rule -> branch name pattern `main`:

| setting | value | why |
|---|---|---|
| Require a pull request before merging | on | the gate is only meaningful if a merge is reviewed |
| Required approvals | 1 | a single maintainer; raise it when there is more than one |
| Dismiss stale approvals on new commits | on | an approval of a different diff is not an approval |
| Require status checks to pass | on, check `gate` | that is the job in `.github/workflows/checks.yml` |
| Require branches to be up to date | on | a green run against an old base proves nothing |
| Require conversation resolution | on | a review comment that is ignored is not a review |
| Require linear history | on | matches the incremental publish and keeps `git log` readable |
| Allow force pushes | **off** | history rewriting is how the estate detail leaked once already |
| Allow deletions | **off** | |

Also enable **Require review from Code Owners** once a maintainers team exists and a `CODEOWNERS`
file is added. A `CODEOWNERS` file referencing a team that does not exist is worse than none: the
requirement cannot be satisfied and every PR shows a warning.

## Repository metadata

| field | value |
|---|---|
| Description | `Virtual patching and bounded deception for web servers, with an evidence ledger` |
| Topics | `security`, `waf`, `reverse-proxy`, `rust`, `http2`, `incident-response`, `virtual-patching` |
| Website | unset until there is a docs site |

The current description - "0-day defense for your webservers and apps" - is a promise. The README
substantiates a narrower one; the metadata should match the README.

## Security features

Settings -> Code security:

- **Private vulnerability reporting**: on. `SECURITY.md` points at it, and a policy that offers a
  private channel which is switched off is a policy that teaches people to file in public.
- **Dependabot alerts** and **Dependabot security updates**: on. `.github/dependabot.yml` schedules
  weekly version updates; security updates are immediate.
- **Secret scanning** and **push protection**: on for the public repository. Push protection is what
  would have stopped the exporter's `data/` regression at the boundary rather than after review.

## Why the bot is not given `administration`

An agent that can push is an agent that can change what runs in CI (`workflows: write` already
allows that). An agent that can also edit branch protection can remove the requirement that its own
work be reviewed. The two powers together are self-authorising; keep them apart.
