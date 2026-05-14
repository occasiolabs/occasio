# EDR-Detector calibration

The four built-in anomaly detectors (`src/anomaly/detectors/*`) shipped with starter thresholds. This doc records what those thresholds do on a real, day-to-day Occasio chain, and what was tuned after measuring.

## Why the thresholds matter

Occasio markets the anomaly layer as EDR — a category whose buyers (CISOs, Compliance) judge tools by the false-positive rate on normal activity. *"How often does this fire when nothing is wrong?"* is a hard, specific question. Starter thresholds without an empirical baseline are a credibility risk.

The calibration script `scripts/calibrate-anomaly-detectors.js` slides a 15-minute window across an audit chain in 5-minute steps, runs every detector on every window, and tallies alerts by severity. Run it against any sufficiently large chain (≥ ~500 rows) to validate the defaults against your own usage.

## Calibration run

**Chain:** `~/.occasio/pipeline-events.jsonl`
**Span:** 3.2 days (2026-05-11 → 2026-05-14)
**Rows:** 2522
**Windows evaluated:** 911 (≈ 12 per hour)

The chain includes a mix of normal coding work plus several adversarial harness/redteam scenarios run during development, so it is *not* purely benign — the spikes the detectors flag are partially real attacks, partially noisy thresholds. The goal of the tuning was to keep the real signal (HIGH) loud while quieting noise from normal activity.

### Before tuning

| Detector | Total | HIGH | MED | LOW | Per hour | Verdict |
|---|---:|---:|---:|---:|---:|---|
| `deny-rate` | 3 | 3 | 0 | 0 | 0.04 | calibrated — fires only on real burst |
| `file-read-volume` | 1 | 0 | 1 | 0 | 0.01 | calibrated |
| `unknown-tool-input` | 27 | 0 | 27 | 0 | 0.36 | **too noisy** — MEDIUM on every novel non-privileged shape |
| `secret-redact-rate` | 21 | 8 | 13 | 0 | 0.28 | **too noisy** — MEDIUM on every cold-start redaction |

### After tuning

| Detector | Total | HIGH | MED | LOW | Per hour | Verdict |
|---|---:|---:|---:|---:|---:|---|
| `deny-rate` | 3 | 3 | 0 | 0 | 0.04 | unchanged |
| `file-read-volume` | 1 | 0 | 1 | 0 | 0.01 | unchanged |
| `unknown-tool-input` | 24 | 0 | 0 | 24 | 0 MED+HIGH/h | non-privileged novelty now LOW; privileged-key path still HIGH |
| `secret-redact-rate` | 21 | 8 | 10 | 3 | 0.20 MED+HIGH/h | cold-start single-redactions now LOW; bursts (≥5) stay MEDIUM |

The HIGH-severity counts for `secret-redact-rate` are real spikes (e.g. ×117.8 over baseline) from harness runs producing secret-pattern matches on synthetic fixtures. On a chain without adversarial sessions the count would be near zero.

## What was tuned

### `src/anomaly/detectors/unknown-tool-input.js`

- `COLD_START_MIN_ROWS`: `50 → 200`. The detector needs more history to build a real fingerprint set before alerting on "novelty".
- Severity: non-privileged-key novelty is now **LOW** (was MEDIUM). Visible to SIEM consumers via `--json`, not loud for human review.
- Privileged-key novelty (`env`, `sudo`, `exec`, `seccomp`, etc.) remains **HIGH**.

### `src/anomaly/detectors/secret-redact-rate.js`

- Cold-start severity is now scaled by burst size: `< 5` redactions in window → **LOW**, `≥ 5` → **MEDIUM**. Compliance still sees every redaction in the JSON output; reviewers are not paged on test-fixture single-events.
- Once history is ≥ `MIN_HISTORY_FOR_RATE` (200), the existing multiplier logic takes over and HIGH-severity firing on real bursts is unchanged.

### `src/anomaly/detectors/deny-rate.js` and `src/anomaly/detectors/file-read-volume.js`

Unchanged. Calibration confirmed the defaults fire only on real spikes.

## How to re-run

```bash
node scripts/calibrate-anomaly-detectors.js
# JSON output for downstream tooling:
node scripts/calibrate-anomaly-detectors.js --json > calibration.json
# Override the window size or step:
node scripts/calibrate-anomaly-detectors.js --window 30m --step 10m
```

The script prints per-detector tallies, alert rates, one example per severity level, and a heuristic suggestion ("threshold likely too tight" if a detector fires >1 HIGH/day on normal usage). Use the suggestion as a starting point, not a verdict — your chain's activity profile may legitimately push a detector higher than the heuristic expects.

## What this is not

- **Not a replacement for adversarial validation.** Calibration tells us whether the threshold is too tight for normal use. It does not tell us whether the threshold is loose enough to catch genuine attacks. That is the job of `occasio demo anomalies` (which constructs a synthetic adversarial chain that must trigger all four detectors) and the [EDR demo walkthrough](edr-demo.md) (which runs a real Claude Code session against the policy and confirms the detectors fire on the resulting chain).
- **Not a static contract.** Defaults are tuned against one user's chain over 3 days. A production deployment should re-calibrate against its own audit history. Plan: lift the thresholds into `policy.yml` as overridable values once the schema for that is agreed.
- **Not a guarantee of zero false positives.** A `MEDIUM` `secret-redact-rate` alert can fire when someone is legitimately editing a config file full of pattern-matching secrets. The right reading of any single alert is "look at the implicated rows and decide", not "block production".
