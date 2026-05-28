# Deployment models for AI agent observability

There are several tools in the AI-agent observability and governance space. They differ along feature axes, and they also differ along a more fundamental axis: where the tool actually runs, and which party sees the data. This page describes the latter. It is not a feature comparison.

## Where each tool runs, and what its vendor observes

| Tool | Runtime location | Data observed by vendor | Account required | Works offline |
|---|---|---|---|---|
| LangSmith | Vendor cloud | Prompts, responses, tool calls, traces | Yes | No |
| Helicone | Vendor cloud proxy (managed); self-host available | Cloud tier observes all prompts and responses passing through the proxy. Self-host is local. | Yes for cloud | Self-host only |
| Langfuse Cloud | Vendor cloud | Prompts, responses, traces, evaluations | Yes | No |
| Langfuse self-hosted | Your infrastructure | Only the operator of the deployment | No vendor account needed | Yes |
| Honeyhive | Vendor cloud | Prompts, responses, traces | Yes | No |
| Arize Phoenix self-hosted | Your infrastructure | Only the operator of the deployment | No vendor account needed | Yes |
| Occasio | Local process on your machine | Nothing reaches Occasio Labs or any third party. Outbound traffic goes to whichever LLM endpoint you configured, authenticated with your own API key. | No | Yes |

The cell values above describe where each tool was designed to run and which party can observe traffic in its default configuration. For tools that ship both a cloud tier and a self-host option, the rows separate the two so the architectural placement is unambiguous.

## What this table is and is not saying

This is a descriptive comparison along one dimension: where the tool runs and what its operator sees. SaaS observability tools are a legitimate category. They exist for valid reasons (zero-setup onboarding, cross-team aggregation, hosted dashboards, managed retention), and a team that has chosen the SaaS model will find them well-engineered for that model.

This table is meant to help a reader who is matching a requirement to a category. Three common requirements that lead to the local-first row:

- The data being processed is regulated or contractually restricted from leaving the local environment (healthcare, defence, EU data residency).
- The team wants no third-party dependency in the path between an AI agent and the LLM provider.
- The team wants the audit artefact (the thing presented to an auditor or compliance reviewer) to be self-contained and verifiable without a vendor relationship.

If none of those apply, a SaaS observability tool may serve the team better than Occasio. If any of them apply, the architectural placement matters and a local-first tool is the only category that fits structurally.

## Related

- [`docs/WHY-LOCAL.md`](WHY-LOCAL.md) describes the Occasio architecture in detail.
- [`docs/SUSTAINABILITY.md`](SUSTAINABILITY.md) describes how a local-first product is funded.
