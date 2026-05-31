# Show HN kit

Show HN is a one-shot, high-variance event. Fire it in **week 3**, only after
the demo video exists. Post **Tue–Thu, 8–10am ET**. Be in the thread for the
first 3+ hours. Win condition is not the front page — it's a few real users and
a handful of GitHub stars that compound.

Hard lesson from the comparable that died (NotaryOS: 1 point, 350 clones, 0
stars): it led with the *mechanism* ("cryptographic proof of what your agent
didn't do"). HN's reflex to a crypto/audit headline is "signatures don't
*prevent* anything — so what does this *stop*?" Lead with the danger and the
**block**. The signature is the receipt, not the pitch.

---

## Title options (pick one — name the danger + the block, never "cryptographic")
1. **Show HN: Occasio – see (and prove) what your AI coding agent actually did**
2. **Show HN: Occasio – block what your AI agent does to your machine, then prove it**
3. **Show HN: A local black-box recorder for Claude Code / MCP agents**

Avoid: "cryptographic", "tamper-evident", "attestation", "blockchain",
"governance" in the title. They lower trust on HN. Save them for the body.

---

## Post body (paste, then trim to your voice)

> I build with Claude Code and Cline daily, and the thing that kept bugging me:
> the agent has my shell, my files, and my MCP servers — and I had no real record
> of what it actually did. A normal log doesn't help, because I (or anything on
> my box) can edit it after the fact.
>
> Occasio is a local proxy that sits between the agent and the world. It records
> every tool call locally, can block dangerous ones before they run (e.g. strip a
> secret out of the outbound request before it ever reaches the model), and writes
> a hash-chained, Sigstore-signed record you can hand to someone else to verify
> offline — no account, no calling home.
>
> It's local-first with no telemetry (that's a hard rule, not a setting). Uses
> standard Sigstore + in-toto, not hand-rolled crypto. Node, `npm install -g
> @occasiolabs/occasio`. Demo video below; repo has a "verify in 60 seconds" doc.
>
> Honest about the boundary: the chain is tamper-*evident* (post-hoc edits break
> the SHA-256 walk and cascade), and the signed attestation anchors a state to a
> public Rekor timestamp. It does not claim to stop a machine owner who rewrites
> the whole chain and re-signs — that produces a new, later, publicly-logged Rekor
> entry instead. Happy to go deep on the threat model.
>
> [demo video] · useoccasio.com · github.com/occasiolabs/occasio

---

## Founder first comment (post immediately after submitting)
> Quick technical notes for the HN crowd:
> - Why this isn't "just a log": the record is hash-chained from a GENESIS
>   sentinel; any edit changes a row's hash and breaks every link after it.
>   Verify it yourself with the shipped Python walker or stock `cosign` — none of
>   it trusts Occasio's own verifier.
> - Why standard crypto: Sigstore (Fulcio + Rekor) and in-toto, the same rails
>   npm/PyPI provenance uses. No new trust root, no key management.
> - What it actually prevents today: denied files/secrets are stripped from the
>   outbound request body before it leaves your machine — not just logged.
> - It's read-mostly and conservative: anything it can't safely intercept is
>   recorded as a coverage gap rather than silently dropped.
> Ask me anything — especially about where it's weak.

---

## Prepared answers to the predictable objections
- **"Signatures don't prevent attacks."** Correct — prevention is the policy
  engine (block/strip before execution); the signature is for *proving what
  happened* after, to a third party. Two separate jobs.
- **"What stops me from just not running Occasio / rewriting the chain?"** Nothing
  stops a machine owner from not running it — same as any local tool. A full
  rewrite + re-sign is detectable because it creates a new, later Rekor entry; an
  *un-signed* local chain is tamper-evident but not anchored, and we say so on the
  page. Honest scope beats overclaiming.
- **"Isn't this just SLSA / observability?"** SLSA attests the *build*;
  observability tools *log* and can be edited. Occasio attests *what the agent did
  at runtime*, verifiably. Different leg of the stool (see docs/SUPPLY-CHAIN-TRIANGLE.md).
- **"Telemetry?"** None. No phone-home, ever. `occasio doctor --paranoid` shows
  exactly two runtime deps and no network egress.

## Don't
- Don't lead any reply with compliance/EU-AI-Act — it reads as enterprise
  marketing here. Mention it only if someone asks about audits.
- Don't argue. Concede weak points fast; HN rewards candor.
