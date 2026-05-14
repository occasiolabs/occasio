'use strict';

/**
 * unknown-tool-input — alert when a tool is invoked with a `tool_inputs`
 * shape (sorted-key fingerprint) that has never appeared in history.
 *
 * Catches "agent now passes a flag I've never seen it pass before" — e.g.
 * a Bash call with `--privileged`, a Read with an unexpected option, a new
 * MCP tool variant. Cold start: warm up over COLD_START_MIN_ROWS chain
 * rows before firing.
 */

const ID    = 'unknown-tool-input';
const LABEL = 'Unknown tool-input shape';

// Calibrated against a ~3-day real audit chain (2518 rows of normal
// coding usage). Pre-tune the detector fired 27 times in 3.2 days at
// MEDIUM severity on benign new fingerprints (e.g. `grep` first called
// with only a `path` key). After raising the cold-start floor and
// dropping non-privileged novelty to LOW, the rate drops to ~1/day on
// normal use while privileged-key novelty still fires HIGH. See
// docs/edr-calibration.md for the run that produced these numbers.
const COLD_START_MIN_ROWS = 200;
// Keys that suggest privilege escalation or sandbox escape — novelty on
// these is escalated to HIGH. Everything else: LOW (logged but not loud).
const PRIVILEGED_KEY_RE = /\b(env|privileged|sudo|raw|exec|eval|stdin|cap|caps|seccomp)\b/;

// Fingerprint = `${tool_name}:${sorted comma-separated tool_inputs keys}`.
// Empty inputs → `${tool_name}:`. Non-object inputs are ignored (we only
// fingerprint shape, not values).
function fingerprint(row) {
  if (!row.tool_name) return null;
  const inputs = row.tool_inputs;
  let keys = '';
  if (inputs && typeof inputs === 'object' && !Array.isArray(inputs)) {
    keys = Object.keys(inputs).filter(k => inputs[k] !== undefined).sort().join(',');
  }
  return `${String(row.tool_name).toLowerCase()}:${keys}`;
}

function evaluate(windowRows, historicalRows, _opts) {
  if (historicalRows.length < COLD_START_MIN_ROWS) return [];

  const knownFingerprints = new Set();
  for (const r of historicalRows) {
    if (r.kind && r.kind !== 'tool_call') continue;
    const fp = fingerprint(r);
    if (fp) knownFingerprints.add(fp);
  }

  // Group window rows by their (novel) fingerprint so we emit one alert per
  // new shape, not one per row.
  const byFp = new Map();
  for (const r of windowRows) {
    if (r.kind && r.kind !== 'tool_call') continue;
    const fp = fingerprint(r);
    if (!fp || knownFingerprints.has(fp)) continue;
    if (!byFp.has(fp)) byFp.set(fp, []);
    byFp.get(fp).push(r);
  }
  if (byFp.size === 0) return [];

  const alerts = [];
  for (const [fp, rows] of byFp) {
    const [toolName, keysJoined] = fp.split(':');
    const keysDisplay = keysJoined ? `{${keysJoined}}` : '{}';
    // Privileged-key novelty is loud (HIGH). Everything else is LOW
    // — visible in JSON/SIEM consumers but not noisy for human review.
    // Calibration showed MEDIUM on non-privileged novelty was the
    // largest source of false positives on normal usage.
    const high = PRIVILEGED_KEY_RE.test(keysJoined);
    alerts.push({
      severity: high ? 'high' : 'low',
      observed: rows.length,
      baseline: 0,
      message: `Tool '${toolName}' invoked with previously-unseen input shape ${keysDisplay} (${rows.length}× in current window)`,
      rows_implicated: rows.filter(r => typeof r.hash === 'string').slice(0, 5).map(r => r.hash),
    });
  }
  return alerts;
}

module.exports = { id: ID, label: LABEL, evaluate, _fingerprint: fingerprint };
