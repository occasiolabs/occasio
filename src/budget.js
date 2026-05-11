'use strict';

/**
 * budget.js — Pure budget-enforcement helpers.
 * No I/O.  Import in index.js and test-interceptor.js.
 */

const WARN_THRESHOLD = 0.80;   // emit warning once at 80 % of budget
const BUDGET_EXCEEDED_EVENT = 'budget_exceeded';

/**
 * Given current session spend and the configured budget limit, return the
 * enforcement state that the caller should act on.
 *
 * @param {number}       spent   Accumulated session cost so far (before this request)
 * @param {number|null}  budget  Dollar limit (null = no budget)
 * @returns {{ exceeded: boolean, warnNow: boolean, pct: number|null }}
 *   exceeded  – true if spend >= budget (block the request)
 *   warnNow   – true if spend crossed the warning threshold (fire at most once)
 *   pct       – spend / budget ratio (null when no budget)
 */
function budgetStatus(spent, budget) {
  if (budget == null || budget <= 0) return { exceeded: false, warnNow: false, pct: null };
  const pct = spent / budget;
  return {
    exceeded: pct >= 1.0,
    warnNow:  pct >= WARN_THRESHOLD,
    pct,
  };
}

/**
 * Format a spend-vs-budget string for display.
 * e.g. "$0.85 / $1.0000 (85%)"
 */
function fmtBudget(spent, budget) {
  if (budget == null) return '';
  const pct = Math.min(999, Math.round(spent / budget * 100));
  return `$${spent.toFixed(4)} / $${budget.toFixed(4)} (${pct}%)`;
}

module.exports = { budgetStatus, fmtBudget, WARN_THRESHOLD, BUDGET_EXCEEDED_EVENT };
