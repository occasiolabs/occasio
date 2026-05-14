# `src/demo/` — production CLI demos

The files in this folder back the `localfirst demo <name>` CLI subcommands. They are **production features**, not throwaway scaffolding: they ship in the npm package, are linked from the project README, and are the first-impression artifact for design partners, investors, and auditors evaluating the project.

## What "demo" means here

Each file in this folder implements one runnable CLI demo that exercises a full LocalFirst pipeline end-to-end against synthetic data, in seconds, with no external dependencies (no API key, no GitHub Actions, no network). The synthetic-data choice is deliberate:

- Demos never touch the user's real `~/.localfirst/pipeline-events.jsonl` audit chain
- Demos do not require credentials or sign-in
- Demos exercise the same code paths the real CLIs use (`buildAttestation`, `runDetectors`, etc.) — they wrap the production primitives rather than re-implementing them
- A passing `localfirst demo X` is also a smoke test for the underlying schiene

## Files

| File | CLI command | What it demonstrates |
|---|---|---|
| `attest-demo.js` | `localfirst demo attest` | Build → verify → check-run-preview for the attestation pipeline |
| `anomalies-demo.js` | `localfirst demo anomalies` | Synthetic adversarial chain → all 4 EDR detectors fire |

## Naming convention

`demo/<feature>-demo.js` exports `run<Feature>DemoCli(args)` and is wired into the top-level CLI dispatcher (`src/index.js`) under `cmd === 'demo' && args[1] === '<feature>'`. The two-token CLI form (`localfirst demo <feature>`) keeps these visible as a coherent demo surface in `localfirst --help` without polluting the top-level command namespace.

If you need a CLI that operates against real user data (not synthetic), it does not belong here — put it directly in `src/<feature>/cli.js` next to the production primitives.

## Why not put these in `examples/`

`examples/` (sibling of `src/`) is for static example files users copy into their own setup — `policy.yml` templates, GitHub Action YAML snippets, JSONL fixtures. The contents of `examples/` are read by the user, not executed by LocalFirst.

`src/demo/` is for executable demos that ship as installable CLI commands. Different distribution path, different audience.
