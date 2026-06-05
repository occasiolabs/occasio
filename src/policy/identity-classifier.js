'use strict';

/**
 * identity-classifier.js — classify identity-bearing shell commands.
 *
 * One rule governs the whole gate: an AI agent may *request* an identity, it
 * may not silently *assume* one. This module recognises the commands through
 * which an agent borrows or exfiltrates an identity (ssh into a server, drive a
 * cloud control plane, escalate to root, dump env/secrets, read private keys)
 * and tags each with a stable classification the policy engine and audit log
 * consume.
 *
 * Pure and deterministic — no filesystem, no network, no clock (mirrors
 * src/policy/shell-path.js). `classify(command)` returns null for any command
 * it does not recognise, leaving the existing routing untouched. Built-in
 * patterns are the floor; policy (deny_commands / identity_approval) is the
 * authoritative enforcement layer that sits on top.
 *
 * Returned shape (or null):
 *   {
 *     action:        'secret_identity_access' | 'identity_borrow'
 *                  | 'cloud_control_plane'    | 'service_control',
 *     identity_type: stable string (e.g. 'ssh', 'azure_cli', 'ssh_private_key'),
 *     target_class:  'secrets' | 'production' | 'cloud' | 'unknown',
 *     risk:          'low' | 'medium' | 'high',
 *     default:       'deny' | 'require_approval',   // disposition when no
 *                                                   // explicit policy rule applies
 *     reason:        stable reason code,
 *     matched_rule:  name of the built-in rule that fired,
 *   }
 */

// Ordered rules — first match wins. Order matters: secret-access (deny) rules
// come before borrow (approval) rules so a command that both reads a key and
// opens a session is classified by its most dangerous facet first.
const RULES = Object.freeze([
  // ── secret / identity exfiltration → deny ────────────────────────────────
  {
    matched_rule: 'env_dump',
    regex: /\b(printenv|env)\b|source\s+\.env|\.env\b/i,
    action: 'secret_identity_access',
    identity_type: 'environment_secrets',
    target_class: 'secrets',
    risk: 'high',
    default: 'deny',
    reason: 'env_dump',
  },
  {
    // Live-env dump via the /proc/<pid>/environ file, or shell builtins that
    // print the environment (bare `set`, `declare -p`, `export -p`).
    matched_rule: 'env_dump_indirect',
    regex: /\/proc\/[^/]*\/environ|\benviron\b|(^|[\s;&|])set\s*($|[;&|])|\b(declare|export)\s+-p\b/i,
    action: 'secret_identity_access',
    identity_type: 'environment_secrets',
    target_class: 'secrets',
    risk: 'high',
    default: 'deny',
    reason: 'env_dump_indirect',
  },
  {
    matched_rule: 'ssh_private_key_read',
    regex: /\.ssh[\\/]|id_(?:rsa|ed25519|ecdsa|dsa)\b/i,
    action: 'secret_identity_access',
    identity_type: 'ssh_private_key',
    target_class: 'secrets',
    risk: 'high',
    default: 'deny',
    reason: 'ssh_private_key_access',
  },

  // ── identity borrow → require human approval ─────────────────────────────
  {
    matched_rule: 'ssh_session',
    regex: /\bssh\b|\bscp\b|\brsync\b.*:|\bparamiko\b|\bfabric\b/i,
    action: 'identity_borrow',
    identity_type: 'ssh',
    target_class: 'production',
    risk: 'high',
    default: 'require_approval',
    reason: 'production_ssh',
  },
  {
    matched_rule: 'cloud_cli',
    regex: /\baz\b|management\.azure\.com|login\.microsoftonline\.com|169\.254\.169\.254/i,
    action: 'cloud_control_plane',
    identity_type: 'azure_cli',
    target_class: 'cloud',
    risk: 'high',
    default: 'require_approval',
    reason: 'cloud_control_plane',
  },
  {
    matched_rule: 'privilege_escalation',
    regex: /\b(sudo|systemctl|pkexec|doas)\b|(^|[\s;&|])su\b/i,
    action: 'service_control',
    identity_type: 'root',
    target_class: 'production',
    risk: 'high',
    default: 'require_approval',
    reason: 'privileged_service_control',
  },
  {
    matched_rule: 'git_push',
    regex: /git\s+push\b/i,
    action: 'identity_borrow',
    identity_type: 'git_write',
    target_class: 'unknown',
    risk: 'medium',
    default: 'require_approval',
    reason: 'git_write',
  },
]);

/**
 * Classify a shell command string.
 *
 * @param {string} command  raw Bash/PowerShell command
 * @param {object} [ctx]    reserved for future actor/context-aware rules
 * @returns {null | {action, identity_type, target_class, risk, default, reason, matched_rule}}
 */
function classify(command, ctx) { // eslint-disable-line no-unused-vars
  if (typeof command !== 'string' || !command.trim()) return null;
  for (const rule of RULES) {
    if (rule.regex.test(command)) {
      return {
        action:        rule.action,
        identity_type: rule.identity_type,
        target_class:  rule.target_class,
        risk:          rule.risk,
        default:       rule.default,
        reason:        rule.reason,
        matched_rule:  rule.matched_rule,
      };
    }
  }
  return null;
}

module.exports = { classify, RULES };
