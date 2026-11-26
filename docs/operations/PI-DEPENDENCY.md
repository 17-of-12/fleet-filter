# The agent runtime this project depends on

The unattended side of fleet-filter - fetching CVEs, writing signatures, reproducing exploits,
releasing - is not a set of cron jobs with if-statements. It is a coding agent that is given a skill,
a work item and a checklist, and left running. That agent runtime is a hard dependency, and this
document says exactly what is depended on so the dependency can be pinned, replaced, or audited.

## What is required

| Requirement | Value | Why it is required |
|---|---|---|
| `pi` coding agent | 1.5.0 or later on `PATH` | Every stage of the loop is a `pi` invocation |
| the `subagent` extension | `~/.pi/agent/extensions/subagent/index.ts` | The review stage dispatches a read-only reviewer; without it the release cannot be reviewed |
| a local model provider | configured in `~/.pi/agent/settings.json` | The loop must not depend on a remote API |
| the project skill | `skills/exploit-signature-pipeline.md` in this repository | Loaded into the agent's system prompt; the workflow itself |

`bin/pi-preflight.sh` checks each of the above, plus the completion checklist, and exits non-zero
naming the missing item. The worker runs it before dispatching, so a broken runtime fails as a broken
runtime rather than as an agent that quietly does nothing. It cannot prove the provider answers - only
that one is configured - which is why a session that reaches the model and fails is still the test that
matters.

## How the runtime is driven

Four flags matter, and each is load-bearing:

| Flag | Used for | What happens without it |
|---|---|---|
| `--skill PATH` | puts the workflow in the system prompt before the first turn | the agent spends its first turns exploring the tree, and decides for itself what to skip |
| `--print` | one-shot, non-interactive | the process waits for a human that is not there |
| `--system-prompt PATH` / `--append-system-prompt` | the reviewer's instructions | `pi` has no `--agent` flag headless, so the agent definition is read and passed explicitly |
| `--tools LIST` | restricts the reviewer to read-only tools | a reviewer that can write is not a reviewer |
| `--model NAME` | pins the model, overriding the default provider | the local-model policy is enforced by the invocation, not by a config file somewhere |

Exit status is the contract: `0` means the session finished, non-zero means it did not, and the work
item stays queued. Nothing parses the agent's prose for success.

## The subagent extension

The reviewer is a subagent: the working session spawns it, it reads the diff and the git record, and
it returns a verdict. The extension is not vendored into this repository - it belongs to the runtime
installation, and copying it would mean maintaining a fork of a moving target.

What this project depends on from it:

- the `subagent` tool, callable from a session with `{ agent, task }`
- agent definitions discovered under `~/.pi/agent/agents/*.md` with `name`, `description`, `tools`
  and `model` front matter
- the subagent's output returned as text to the calling session

If the extension's agent-definition format changes, `bin/review-packet.sh` and the release contract in
`bin/release-cve.sh` are what need updating.

## The review loop runs on its own timer

A session that opens a pull request has a wall-clock budget, and reviewing properly does not fit in
whatever is left of it. So the review is its own unit: `bin/pr-review-worker.sh` on a ten-minute
timer asks "is there an open release pull request with a green gate and no verdict", and if there is,
it dispatches a session that spawns an adversarial reviewer, verifies its claims, posts the verdict and
merges on PASS. The queue is the pull requests themselves, so a session that times out leaves work for
the next one instead of leaving it for a person.

## Why not a bespoke harness

Because the interesting part is not the process plumbing. Fetching a CVE, reading a PoC, writing a
signature and proving it does not block an exploit is judgement work, and the judgement has to be
somewhere. Putting it in a coding agent with a skill, a checklist and a read-only reviewer is what
makes the loop unattended. The cost is this dependency, stated here so it is a decision rather than a
discovery.

## Sharing skills

A skill is prose, so no gate reads it. If a skill is shared outside this deployment it must first pass
`bin/skill-lint.py`, which refuses estate identifiers, private addresses, internal host names,
personal paths, work-item references and unresolved questions. `bin/check.sh --all` runs it over
`skills/*.md`, so a shared skill carrying internal material fails the gate rather than being published.
