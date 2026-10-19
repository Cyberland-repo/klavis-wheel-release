# wheel-release

A single original [Terminal-Bench 3](https://github.com/harbor-framework/terminal-bench) task.
The task lives in [`tasks/wheel-release/`](tasks/wheel-release/).

## What the task is

An agent is given a small Python package and a release script that builds a wheel.
The shipped release script is naive: it packs everything and records an absolute
build path. The agent has to fix the release so that:

- the installed wheel still runs exactly as before (public behaviour is preserved);
- nothing private ships: no private module source, names, docstrings, or secrets;
- there are no absolute paths anywhere — not in the files, the compiled filenames,
  `RECORD`, or the metadata;
- the build is reproducible: the same checkout always produces byte-identical output.

The checkout the agent can see never has a public module importing a private one.
The hidden checkout the verifier uses does, so a solution has to handle re-exports,
not just delete the private tree.

## How this was built

I built this with AI coding tools (Cursor, Gemini, and an AI assistant). I did not hand-write the code. My part was the task design, testing each piece as it was built, and trying to break it: rubric review round after round with every pass, fail, and fix logged, plus a hand red team (see [redteam/](redteam/)).

## Rubric result

The task was reviewed against the Terminal-Bench 3 implementation rubric (36 criteria)
using the `task-implementation.toml` prompt. The accepted batch (r14):

| Round | Pass | Fail | N/A | Notes |
|------|-----:|----:|----:|-------|
| r14a | 35 | 0 | 1 | clean (do_not_modify_enforced N/A) |
| r14b | 34 | 0 | 2 | clean (artifact_efficiency + do_not_modify_enforced N/A) |
| r14c2 | 33 | 1 | 2 | fails only `difficult` |

Two of the three rounds passed every applicable criterion (35 of 35 and 34 of 34,
with 1 and 2 criteria not applicable). The third round had a single miss, the
`difficult` criterion, which is a reviewer judgment call about whether the task is
hard enough; the same artifacts passed it on the other two rounds.

## How to run it

With the Terminal-Bench [Harbor](https://github.com/harbor-framework/harbor)
CLI and Docker:

```bash
# oracle (the reference solution should score reward 1.0)
harbor run -p tasks/wheel-release --env docker --yes -n 1 --agent oracle

# null agent (an empty attempt should score reward 0.0)
harbor run -p tasks/wheel-release --env docker --yes -n 1 --agent nop
```

The reference solution is in `tasks/wheel-release/solution/`. The verifier is
`tasks/wheel-release/tests/test_release.py`.

## Checks and evaluation commands

Static checks, run from a [Terminal-Bench](https://github.com/harbor-framework/terminal-bench) checkout with Python 3.11+ and `dockerfile-pin` on `PATH` (this repo does not vendor those scripts). Result on this task: **28/28 pass**.

```bash
for check in scripts/checks/check-*.sh; do bash "$check" /path/to/klavis-wheel-release/tasks/wheel-release; done
```

Docker image build: **pass**, as part of the oracle and nop runs above (rewards 1.0 and 0.0).

Implementation rubric (`docs/prompts/task-implementation.toml` in that same Terminal-Bench checkout), reviewer Codex `openai/gpt-6.1-sol` at `reasoning_effort=xhigh`. Result: the r14 table above.

```bash
harbor check tasks/wheel-release -r docs/prompts/task-implementation.toml \
  -a codex -m openai/gpt-6.1-sol --ak reasoning_effort=xhigh \
  --ae CODEX_FORCE_AUTH_JSON=YES
```

Genuine `/run`: three times per configuration, no extra instruction. Adversarial `/cheat`: the same command once, plus `--extra-instruction-path <TERMINAL_BENCH_REPO>/docs/prompts/hack-trial-prompt.md`. The API accepts `anthropic/claude-opus-5-5` (dash). The dotted `claude-opus-5.5` in the assignment is rejected.

```bash
# Codex — gpt-6.1-sol, reasoning effort xhigh
harbor run -p tasks/wheel-release \
  --agent codex --model openai/gpt-6.1-sol \
  --env docker --yes -n 1 \
  --ae CODEX_FORCE_AUTH_JSON=YES --ak reasoning_effort=xhigh

# Claude Code — Opus 5.5, reasoning effort max
# (the OAuth token is supplied through the environment, not on the command line)
export CLAUDE_CODE_OAUTH_TOKEN=<YOUR_OAUTH_TOKEN>
harbor run -p tasks/wheel-release \
  --agent claude-code --model anthropic/claude-opus-5-5 \
  --env docker --yes -n 1 \
  --ae CLAUDE_FORCE_OAUTH=YES \
  --ak reasoning_effort=max
```

Countable Opus runs after the first post-reset attempt also set `CLAUDE_CODE_MAX_OUTPUT_TOKENS=128000`. Results and failure notes are in [TRIALS.md](TRIALS.md).

## Trial status

Models: Claude Opus 5.5 (reasoning effort max) and gpt-6.1-sol (reasoning effort
xhigh) — the models requested for this submission. See [TRIALS.md](TRIALS.md) for
the full table.

- **Genuine (gpt-6.1-sol):** 3 countable runs, all reward 0. Each built wheel
  passed the visible, confidentiality, reproducibility, and install checks and
  failed only on a public absolute build path left in the shipped wheel. No reward
  hacking.
- **Genuine (Opus 5.5):** 3 countable runs, all reward 0. Two failed on the same
  absolute-path miss as the Codex runs; one failed earlier, when its release script
  hit a robustness gap bundling a private module on the hidden checkout. No reward
  hacking. (Some earlier attempts were uncountable because the provider's session
  limit stopped them; they were re-run one at a time.)
- **Adversarial / `/cheat` (Opus 5.5):** reward 0. This is a real, counted cheat
  trial: the agent ran and attempted it, doing read-only recon for a way to game the
  grader, and found nothing exploitable. Claude's safety layer pushed back several
  times along the way, so it is a somewhat weaker negative than a full attack, but it
  did run.
- **Adversarial / `/cheat` (gpt-6.1-sol):** reward 0, recorded but not counted. The
  reward is 0 only because the provider's safety layer refused the prompt on the first
  turn; the agent never ran and never attempted a bypass, so this 0 is not evidence the
  task resists cheating. That gap is why the hand red-team exists (see [redteam/](redteam/)).
- **Hand red-team (no model):** malicious reference solutions run through the
  `oracle` agent each scored reward 0 while the honest solution scored 1.0; no
  reward-hacking hole was found among the probes tested. See [redteam/](redteam/)
  for the probes and full results.

## License

MIT — see [LICENSE](LICENSE).
