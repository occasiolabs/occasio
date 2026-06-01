# Preflight

`occasio preflight` has two modes:

- **Miner (backward-looking)** — `occasio preflight` reads past logs and prints
  this project's frequent opening-move tool patterns. Source: `src/preflight/miner.js`.
- **Simulator (forward-looking)** — `occasio preflight simulate` predicts
  **allow/block** for candidate actions against the **active policy**, *before*
  the agent runs. Source: `src/preflight/simulate.js`.

## `occasio preflight simulate`

```bash
occasio preflight simulate --read ~/.ssh/id_rsa --read src/app.js   # check reads
occasio preflight simulate --bash "npm test" --grep src --glob "**/*.ts"
occasio preflight simulate --from actions.jsonl                     # {tool,target} per line
occasio preflight simulate --mined                                  # this project's frequent reads
occasio preflight simulate --read ~/.ssh/id_rsa --strict            # exit 1 if any action would block
```

Each candidate action is run through the **same `policy.evaluate()` the runtime
uses** — so the verdict is exactly what would happen during a real run, not a
guess. Blocked actions show the matched rule and how to unblock (the same
explanation `occasio explain` gives):

```
⛔ block  read ~/.ssh/id_rsa  · path-denied
    rule deny_paths[0] = ~/.ssh  (~/.occasio/policy.yml:5)
    → Remove or narrow `~/.ssh` in deny_paths to allow this access.
    → Paths outside the deny list are allowed by default.
✓ allow  read src/app.js  (LOCAL)

  1 allowed · 1 blocked of 2
```

Exit code: `0` (preview). With `--strict`, exit `1` if any action would be
blocked — a CI "would my workflow trip the policy?" gate.

## Boundaries

- Simulates **concrete candidate actions** you supply (or mined read targets) —
  **not** a natural-language task. Turning "implement auth" into a predicted set
  of actions would need an LLM and is out of scope.
- `--mined` only folds in mined **read** paths (the miner stores grep/glob
  *patterns*, not the searched path, so those aren't path-simulated).
- Reflects the active policy faithfully, including the shell-read `~`-expansion
  boundary noted in [`docs/POLICY.md`](POLICY.md).

See also: [`docs/POLICY.md`](POLICY.md) · [`docs/SCAN.md`](SCAN.md).
