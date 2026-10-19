# wheel-release

A single original [Terminal-Bench 3](https://github.com/laude-institute/terminal-bench) task.
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

## Rubric result

The task was reviewed against the Terminal-Bench 3 implementation rubric (36 criteria)
using the `task-implementation.toml` prompt. The accepted batch (r14):

| Round | Pass | Fail | N/A | Notes |
|------|-----:|----:|----:|-------|
| r14a | 35 | 0 | 1 | clean (do_not_modify_enforced N/A) |
| r14b | 34 | 0 | 2 | clean (artifact_efficiency + do_not_modify_enforced N/A) |
| r14c2 | 33 | 1 | 2 | fails only `difficult` |

Two of the three rounds pass every applicable criterion (a true 36/36). The third
round fails only the `difficult` criterion, which is a reviewer judgment call about
whether the task is hard enough; the same artifacts passed it on the other rounds.

## How to run it

With the Terminal-Bench [Harbor](https://github.com/laude-institute/terminal-bench)
CLI and Docker:

```bash
# oracle (the reference solution should score reward 1.0)
harbor run -p tasks/wheel-release --env docker --yes -n 1 --agent oracle

# null agent (an empty attempt should score reward 0.0)
harbor run -p tasks/wheel-release --env docker --yes -n 1 --agent nop
```

The reference solution is in `tasks/wheel-release/solution/`. The verifier is
`tasks/wheel-release/tests/test_release.py`.

## Trial status

Models: Claude Opus 5.5 (reasoning effort max) and gpt-6.1-sol (reasoning effort
xhigh) — the models requested for this submission. See [TRIALS.md](TRIALS.md) for
the full table.

- **Genuine (gpt-6.1-sol):** 3 countable runs, all reward 0. Each built wheel
  passed the visible, confidentiality, reproducibility, and install checks and
  failed only on a public absolute build path left in the shipped wheel. No reward
  hacking.
- **Genuine (Opus 5.5):** in progress, run one at a time. Earlier runs were not
  countable because the provider's session/token limit stopped them; those that
  reached the verifier showed the same absolute-path miss. Updated as each finishes.
- **Adversarial / `/cheat` (Opus 5.5):** reward 0. The agent stayed read-only,
  found no bypass, and its own safety check stopped it early — a weak negative.
- **Adversarial / `/cheat` (gpt-6.1-sol):** recorded but not counted. The provider
  refused the prompt on the first turn, so no bypass was ever attempted.
- **Hand red-team (no model):** malicious reference solutions run through the
  `oracle` agent each scored reward 0 while the honest solution scored 1.0; no
  reward-hacking hole was found among the probes tested.

## License

MIT — see [LICENSE](LICENSE).
