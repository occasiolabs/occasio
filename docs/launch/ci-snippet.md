# Copy-paste CI snippet

This is the asset that feeds the North Star: every public repo that adds a
workflow referencing `@occasiolabs/occasio` is a real adoption signal that
GitHub code-search (and Claude Code users) can find. Keep it tiny and
copy-pasteable. The fuller PR-to-attested-merge flow lives in
[`docs/reference-pipeline.md`](../reference-pipeline.md).

Drop this at `.github/workflows/occasio-attest.yml`. It signs a behavioral
attestation for the run and re-verifies it — the signing step uses GitHub's
keyless OIDC (`id-token: write`), no secrets to manage.

```yaml
name: occasio-attest

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  id-token: write        # required for Sigstore keyless signing

jobs:
  attest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-node@v5
        with:
          node-version: '22'

      - name: Install Occasio
        run: npm install -g @occasiolabs/occasio

      # ── Run your AI-assisted step under Occasio here so it records a chain.
      #    (See docs/reference-pipeline.md for driving Claude Code in CI.)
      #    For a minimal adoption signal you can attest an existing chain file.

      - name: Bundle + sign the evidence
        run: occasio bundle --run "${{ github.run_id }}" --sign --out run.occasio.json

      - name: Verify it (six checks, strict)
        run: occasio verify --strict run.occasio.json

      - name: Summary
        if: always()
        run: |
          {
            echo "### Occasio attestation"
            echo '```json'
            occasio report --format json
            echo '```'
          } >> "$GITHUB_STEP_SUMMARY"
```

## Notes
- `occasio bundle --sign` only signs where an OIDC token is available (GitHub
  Actions with `id-token: write`). Locally it builds an *unsigned* bundle —
  the chain + predicate still verify; signature is marked unsigned. Use
  `occasio verify` (lenient) for an unsigned bundle; `--strict` requires a
  signature, policy binding and git state, and is the audit-grade CI gate.
- `occasio verify --strict` exits non-zero if any of the six checks fail, so it
  gates the job honestly.
- No telemetry: nothing in this workflow calls Occasio Labs. Signing talks only
  to the public Sigstore (Fulcio + Rekor) infrastructure.
- Minimal-adoption variant: even a job that just runs `occasio verify` on a
  committed `run.occasio.json` bundle counts as a public reference.
- Independent re-verification, no Occasio code trusted:
  `python docs/verify_bundle.py run.occasio.json --strict`.
