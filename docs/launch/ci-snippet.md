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

      - name: Sign behavioral attestation
        run: occasio attest --run-id "${{ github.run_id }}" --sign

      - name: Verify it (all three checks)
        run: occasio attest verify occasio-attestation.json

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
- `occasio attest --sign` only works where an OIDC token is available (GitHub
  Actions with `id-token: write`). Locally it builds an *unsigned* attestation —
  the chain + predicate still verify; the Sigstore step is marked skipped.
- `occasio attest verify` exits non-zero if any of the three checks fail, so it
  gates the job honestly.
- No telemetry: nothing in this workflow calls Occasio Labs. Signing talks only
  to the public Sigstore (Fulcio + Rekor) infrastructure.
- Minimal-adoption variant: even a job that just runs `occasio attest verify` on
  a committed attestation bundle counts as a public reference.
