# Occasio Attestation Viewer (static)

Standalone, build-free, single-page viewer for [`agent-attestation/v1`](https://github.com/occasiolabs/occasio/blob/main/spec/agent-attestation/v1/README.md) artifacts.

Designed to be hosted as GitHub Pages at `https://occasiolabs.github.io/attest-view`. The GitHub Action's PR Check links here via the `Details` URL.

## What it does

Drop in (or upload) the three files produced by a Occasio attestation:

| File | Required | Source |
|---|---|---|
| `occasio-attestation.json` | yes | workflow artifact |
| `occasio-attestation.sigstore.json` | optional but recommended | workflow artifact |
| `pipeline-events.jsonl` (chain file) | optional | committed to repo, or downloaded separately |

The page then displays a structured summary, runs two browser-side checks, and surfaces a link to the Rekor transparency log for offline cryptographic verification.

## Verification model

Three checks are rendered, each independent:

| Check | Done by browser? | Replacement when not |
|---|---|---|
| **Sigstore signature** (cert chain → Fulcio, Rekor inclusion proof) | **No** | Rekor URL is shown; run `occasio attest verify`, `cosign verify-blob`, or `sigstore-python` offline. |
| **DSSE payload byte-equivalence** with the attestation predicate | Yes | — |
| **Audit chain integrity** + slice-hash containment | Yes (if `pipeline-events.jsonl` is uploaded) | Offline `occasio audit verify`. |

The page is **honest** that it does not verify Sigstore cryptography in-browser. Bundling Fulcio/Rekor trust roots and the full sigstore-js library client-side is non-trivial and adds friction the viewer doesn't need.

## Hosting

```bash
# Local preview (any static server)
python3 -m http.server 8080
# → http://localhost:8080/
```

For GitHub Pages: the repository's Settings → Pages should point to `main` branch, root path. No build step.

## Files

| File | Purpose |
|---|---|
| `index.html` | Layout + drop zone |
| `viewer.js`  | All logic: ingestion, verification, render |
| `style.css`  | Minimal dark-mode theme, no framework |

## License

Apache-2.0.
