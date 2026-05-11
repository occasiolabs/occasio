'use strict';

/**
 * distiller.js — Output distillation for intercepted tool results.
 *
 * Applies conservative line-count limits to high-volume, low-risk, read-only
 * command output before it re-enters the model as a tool_result.
 *
 * Rules:
 *   grep / rg       → clip at GREP_MAX_LINES
 *   find            → clip at FIND_MAX_LINES
 *   ls / dir / gci  → clip at LS_MAX_LINES
 *   git log         → clip at GIT_LOG_MAX_LINES
 *   test runners    → smart extraction: failures + summary, clip at TEST_MAX_LINES
 *
 * All other commands pass through unchanged.
 * Short output (below threshold) passes through unchanged.
 *
 * result.rawContent is set to the original string when output was distilled,
 * so callers can persist it for replay/debugging.
 */

const GREP_MAX_LINES    = 50;
const FIND_MAX_LINES    = 100;
const LS_MAX_LINES      = 100;
const GIT_LOG_MAX_LINES = 100;
const TEST_MAX_LINES    = 100;

/**
 * Map a command string to its distillation category.
 * Returns null when no rule applies.
 */
function classifyCmd(cmd) {
  if (!cmd) return null;
  const parts = cmd.trim().split(/\s+/);
  const head  = parts[0].toLowerCase();

  if (head === 'grep' || head === 'rg')                          return 'grep';
  if (head === 'find')                                           return 'find';
  if (['ls','eza','exa','lsd','dir'].includes(head))             return 'ls';
  if (/^get-childitem$/i.test(parts[0]))                         return 'ls';
  if (head === 'git' && parts[1] === 'log')                      return 'git-log';

  // Test runners
  if (['jest','vitest','pytest','py.test'].includes(head))       return 'test';
  if (head === 'cargo' && parts[1] === 'test')                   return 'test';
  if (head === 'go'    && parts[1] === 'test')                   return 'test';
  if (['npm','npx','yarn','pnpm'].includes(head)) {
    const sub = (parts[1] || '').toLowerCase();
    if (sub === 'test' || sub === 'jest' || sub === 'vitest' || sub === 'run') {
      // npm run test / yarn run test etc. — only classify as test when sub-cmd is test-like
      if (sub === 'run') {
        const subsub = (parts[2] || '').toLowerCase();
        if (subsub === 'test' || subsub === 'jest' || subsub === 'vitest') return 'test';
      } else {
        return 'test';
      }
    }
  }

  return null;
}

/**
 * Distill a single tool-result output string.
 *
 * @param {string} cmd    The command that produced the output
 * @param {string} output The raw output string
 * @returns {{
 *   content:     string,        // what to send to Anthropic
 *   distilled:   boolean,
 *   savedTokens: number,        // estimated tokens saved (bytes/4)
 *   label:       string,        // human-readable label for logs
 *   rawBytes:    number,        // original byte count (for ledger)
 *   rawContent:  string | null, // original output when distilled; null when not distilled
 * }}
 */
function distill(cmd, output) {
  const rawBytes = Buffer.byteLength(output || '', 'utf8');
  const none = { content: output, distilled: false, savedTokens: 0, label: '', rawBytes, rawContent: null };

  if (!output || !cmd) return none;

  const category = classifyCmd(cmd);
  if (!category) return none;

  // Test output uses smart failure-preserving extraction
  if (category === 'test') return distillTestOutput(output, rawBytes, cmd);

  const lines = output.split('\n');

  let maxLines;
  let unitLabel;
  switch (category) {
    case 'grep':     maxLines = GREP_MAX_LINES;     unitLabel = 'match lines'; break;
    case 'find':     maxLines = FIND_MAX_LINES;     unitLabel = 'paths';       break;
    case 'ls':       maxLines = LS_MAX_LINES;       unitLabel = 'entries';     break;
    case 'git-log':  maxLines = GIT_LOG_MAX_LINES;  unitLabel = 'log lines';   break;
    default: return none;
  }

  if (lines.length <= maxLines) return none;

  const nonEmpty = lines.filter(l => l.trim()).length;
  const content  = lines.slice(0, maxLines).join('\n')
    + `\n[LocalFirst: ${nonEmpty} ${unitLabel} total — showing first ${maxLines}. Full output not re-sent to model.]`;

  const savedBytes  = Math.max(0, rawBytes - Buffer.byteLength(content, 'utf8'));
  const savedTokens = Math.ceil(savedBytes / 4);
  const label       = `${category} clipped ${nonEmpty}→${maxLines} ${unitLabel}`;

  return { content, distilled: true, savedTokens, label, rawBytes, rawContent: output };
}

// Regex matching lines that likely contain test failures or errors.
const FAIL_RE = /\b(FAIL|FAILED|ERROR|error:|✗|×|AssertionError|not ok|ERRORED)\b/;

/**
 * Smart distillation for test-runner output.
 * Keeps all failure-related lines (plus 1 line of context each side) and the
 * last 15 lines (usually the summary).  Clips total to TEST_MAX_LINES.
 */
function distillTestOutput(output, rawBytes, cmd) {
  const lines = output.split('\n');
  const none  = { content: output, distilled: false, savedTokens: 0, label: '', rawBytes, rawContent: null };
  if (lines.length <= TEST_MAX_LINES) return none;

  // Collect indices worth preserving
  const keepIdx = new Set();

  // Failure context lines
  lines.forEach((l, i) => {
    if (FAIL_RE.test(l)) {
      if (i > 0) keepIdx.add(i - 1);
      keepIdx.add(i);
      if (i < lines.length - 1) keepIdx.add(i + 1);
    }
  });

  // Always keep the last 15 lines (pass/fail summary)
  for (let i = Math.max(0, lines.length - 15); i < lines.length; i++) keepIdx.add(i);

  const chosen = [...keepIdx].sort((a, b) => a - b).map(i => lines[i]);
  const totalNonEmpty = lines.filter(l => l.trim()).length;
  const note = `[LocalFirst: test output ${totalNonEmpty} lines — showing ${chosen.length} failure/summary lines. Full output saved for inspection: localfirst distill]`;
  const content = chosen.join('\n') + '\n' + note;

  const savedBytes  = Math.max(0, rawBytes - Buffer.byteLength(content, 'utf8'));
  const savedTokens = Math.ceil(savedBytes / 4);
  const label       = `test clipped ${totalNonEmpty}→${chosen.length} lines (failures+summary)`;

  return { content, distilled: true, savedTokens, label, rawBytes, rawContent: output };
}

module.exports = { distill, classifyCmd, GREP_MAX_LINES, FIND_MAX_LINES, LS_MAX_LINES, GIT_LOG_MAX_LINES, TEST_MAX_LINES, FAIL_RE };
