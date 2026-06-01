# Secret scanning

Occasio has two secret detectors:

1. **Built-in pattern scanner** (`src/analyzer.js` `scanSecrets`) — the default,
   used on the live BLOCK path (`block_secrets_in_tool_results`). Conservative,
   pattern-based.
2. **Richer explainable detectors** (`src/scanner/detectors.js`) — surfaced by
   `occasio scan` and, **opt-in**, on the live path via
   `entropy_secret_detection: true` in `policy.yml`. **Default off.**

This page covers (2). The matched value is **never** printed or stored in
plaintext — only a masked snippet and a SHA-256.

## `occasio scan`

```bash
occasio scan --file <path>      # scan a file
occasio scan --stdin            # scan piped input
occasio scan --file <p> --json  # machine-readable findings
```

Exit code: `1` when any finding exists (CI gate), `0` when clean. Each finding is
explainable:

```
● prefix · github-token · 98% · path:12
    known credential prefix (github-token)
    snippet  ***** ***_***************…
    sha256   cec786cf607e40fa…
```

## Detectors

| detector | what it catches | confidence |
|---|---|---|
| `prefix` | known credential prefixes — `ghp_`/`github_pat_`/`glpat-`, `sk-ant-`, OpenAI `sk-…`, Slack `xox[baprs]-`, AWS `AKIA`/`ASIA`, Google `AIza`, Stripe `sk_live_`/`sk_test_`, `npm_…` | ~0.95–0.98 |
| `jwt` | `header.payload.signature` where the header base64url-decodes to JSON with an `alg` | ~0.95 |
| `env-key` | `KEY=value` where the key matches `SECRET\|TOKEN\|KEY\|PASSWORD\|API\|AUTH\|CREDENTIAL\|PRIVATE` and the value isn't a placeholder | ~0.8 |
| `entropy` | charset-diverse tokens (≥20 chars, Shannon entropy ≥ ~3.5 bits/char) that aren't allowlisted | ~0.4–0.85 |

## Allowlist (false-positive control)

Applied to every detector: placeholders (`changeme`, `your_…`, `<…>`, `xxxx`),
anything containing `EXAMPLE` (e.g. AWS's documented `AKIAIOSFODNN7EXAMPLE`), and a
caller-supplied allowlist (literals or regex sources). The **entropy** detector
additionally skips **UUIDs** and **pure-hex** strings (Git SHAs, checksums,
digests) — the key control that keeps hashes from tripping entropy.

## Redaction ledger (hash-only)

`redactWithLedger(text)` returns the redacted text (`[REDACTED:label]`) plus a
ledger where each entry records `{ detector, label, reason, line, value_sha256,
replacement }` — the SHA-256 and reason, **never the secret**. Suitable for an
audit trail that proves a secret was caught without storing it.

## Boundaries

- The pattern scanner is the default; `entropy_secret_detection` is opt-in and
  off by default, so enabling it (and the extra blocks it can cause in
  `--preset strict`) is an explicit choice.
- Detection is heuristic: entropy is a probability signal, not proof. Use the
  allowlist for controlled false positives; review `scan` output before acting.
- `occasio scan` reads a file/stdin you point it at — it does not scan your whole
  disk.

See also: [`docs/POLICY.md`](POLICY.md) · [`docs/AUDIT.md`](AUDIT.md).
