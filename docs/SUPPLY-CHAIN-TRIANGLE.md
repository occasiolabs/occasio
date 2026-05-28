# Where Occasio sits in the AI supply-chain triangle

Three open specifications describe distinct, complementary properties of a software artefact produced with AI assistance. Each answers a different question; none subsumes the others. Occasio implements the third.

## The three legs

| Specification | Question it answers | Implementations |
|---|---|---|
| [SLSA Provenance v1](https://slsa.dev/spec/v1.0/provenance) | What build process produced this artefact? Who controlled it? | `slsa-github-generator`, `slsa-verifier`, `cosign attest` |
| [CycloneDX AI-BOM](https://cyclonedx.org/capabilities/mlbom/) (ML-BOM 1.6 extensions) | What models, training data, and components were composed into the AI system? | `cyclonedx-cli`, `cyclonedx-node-npm`, vendor exporters |
| [Occasio agent-attestation/v1](../spec/agent-attestation/v1/README.md) | What did the AI agent actually do, file by file, decision by decision, at runtime? | `occasio attest --sign`, `occasio attest verify`, [`docs/attest_verify.py`](attest_verify.py) |

```
                ┌──────────────────────┐
                │   SLSA Provenance    │   build process integrity
                └──────────────────────┘
                          ▲
                          │  attests the artefact
                          │
                          │
   ┌──────────────────┐   │   ┌────────────────────────────────┐
   │  CycloneDX       │ ──┼── │  Occasio agent-attestation/v1  │
   │  ML-BOM / AI-BOM │   │   │                                │
   │                  │   │   │  runtime behavioral integrity  │
   │  composition     │   │   │                                │
   └──────────────────┘   │   └────────────────────────────────┘
                          │
                          ▼
                   the AI-assisted artefact
```

## Why three legs are necessary

A single attestation answers a single question. A reviewer who wants to ship an AI-assisted artefact responsibly needs all three:

- SLSA Provenance proves the artefact came from a known builder running a known workflow. It does not say what happened inside that workflow.
- AI-BOM proves what models and data the system was composed of. It does not say what the running agent did with them.
- Agent-attestation proves what the agent did during this specific session: which files it read, which actions were blocked, which secrets were redacted, under which policy. It does not say what model produced those decisions or what build packaged them.

Each leg holds the chain together for a different attack: tampered build pipeline, undisclosed model component, agent that read files outside its permitted scope. A complete review verifies all three.

## How Occasio fits

Occasio writes a tamper-evident hash-chained audit log of every governed tool call (`tool_call`), every per-request accounting row (`request`), and every policy load (`policy_loaded`). At end of session it produces an [agent-attestation/v1](../spec/agent-attestation/v1/README.md) statement covering a slice of that chain, wrapped in an [in-toto Statement v1](https://github.com/in-toto/attestation) and signed with [Sigstore](https://www.sigstore.dev/) (Fulcio keyless, Rekor transparency log).

The same chain data can be re-emitted as a CycloneDX AI-BOM when the workflow needs both legs in one bundle. Future tooling will land this as `occasio bom export`.

## Verification chain

A consumer verifies the triangle in the order they trust:

1. **SLSA Provenance**: `slsa-verifier verify-artifact`. Establishes the build came from the expected workflow.
2. **AI-BOM**: validate against the [CycloneDX 1.6 schema](https://cyclonedx.org/docs/1.6/json/). Establishes the declared composition.
3. **Agent-attestation**: `occasio attest verify` (Node) or [`docs/attest_verify.py`](attest_verify.py) (Python). Establishes the runtime behavior.

All three steps run offline. None require contacting Occasio Labs or any other vendor. The attestation files travel with the artefact; the verifier code travels with the npm package or the cited spec.

## See also

- [`docs/WHY-LOCAL.md`](WHY-LOCAL.md): why the runtime leg is local-first by architecture, not by promise.
- [`docs/COMPARE.md`](COMPARE.md): deployment-model comparison with cloud-hosted AI observability tools.
- [`spec/agent-attestation/v1/README.md`](../spec/agent-attestation/v1/README.md): the predicate specification.
