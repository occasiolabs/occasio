# Contributing to Occasio

## Setup

```
git clone https://github.com/occasiolabs/occasio.git
cd occasio
npm install
```

Requires Node.js 22 or newer. Windows users should run from a terminal
with developer-mode symlinks enabled.

## Running tests

```
npm test           # full suite (interceptor, audit-chain, attest, policy)
npm run lint       # audit + attest directories (must stay clean)
npm run lint:all   # broader sweep — still being incrementally cleaned
npm run smoke      # smoke test against a recorded session
```

Every change must keep `npm test` green. Pull requests that regress the
audit-chain or policy-path suites will not be merged.

## Code style

- CommonJS, no transpilation. Target Node 22+.
- Two-space indentation, single quotes, semicolons.
- No new dependencies without a strong reason. Zero-dep is an asset.
- No `try {} catch {}` blocks. Either log/audit the failure or leave a
  one-line comment explaining the intentional swallow. Enforced by
  `no-empty` in `eslint.config.js`.
- Audit-row field order is load-bearing — `src/audit/jsonl-auditor.js`
  and `docs/audit_walker.py` must agree on field order, and
  `test-interceptor.js` §32 enforces this. Add new fields at the end of
  the row literal, never in the middle.
- Comments explain *why*, not *what*. Don't restate the code.

## PR process

1. Fork, branch from `main`.
2. Add or update tests for any behavior change. Test files use
   `console.log` + hand-rolled `assert()` — match the surrounding style.
3. Run `npm test` and `npm run lint`.
4. Update `CHANGELOG.md` under `Unreleased`.
5. Open the PR with a short description of what changed and why. Link
   the roadmap section in `docs/ARCHITECTURE.md` if it applies.

## Areas that need contributors

See `docs/ARCHITECTURE.md` for the pipeline overview. The roadmap items
most welcoming of outside help are:

- Test-file modularization (the 7000-line `test-interceptor.js` is the
  biggest velocity drag — splitting one section per PR is a great way
  to start).
- CI matrix coverage (Windows / macOS).
- Lint cleanup outside `src/audit` and `src/attest`.

Avoid:

- Wholesale TypeScript migrations.
- New external dependencies (open an issue first).
- Style-only changes to files you are not otherwise touching.

## Reporting security issues

Do not open a public issue. Email security@occasiolabs.dev with a
reproduction. The hash-chain is the load-bearing security property; any
report that demonstrates silent chain advancement, missing audit rows,
or tamper that the verifier accepts is treated as a P0.
