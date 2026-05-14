'use strict';

/**
 * occasio policy init — write a starter ~/.occasio/policy.yml.
 *
 * Safe by default: refuses to overwrite an existing file unless --force is
 * passed explicitly. After writing, prints the file path and suggests the
 * next commands so the user can inspect and validate immediately.
 *
 * Usage:
 *   occasio policy init                          Write the dev-default starter
 *   occasio policy init --template strict        Locked-down posture
 *   occasio policy init --template finance       Finance-oriented deny_patterns
 *   occasio policy init --force                  Overwrite an existing file
 *   occasio policy init --file <path>            Write to a custom path
 *
 * v0.6.6: starter content is sourced from policy-templates/<name>.yml so the
 * shipped templates are the same files the user can read, copy, and review
 * outside the CLI. Each template carries a $schema directive pointing at the
 * published JSON Schema (schemas/occasio-policy.schema.json).
 */

const fs   = require('fs');
const path = require('path');

// Templates ship as real files under policy-templates/. Lifting the
// content out of a JS string makes the templates inspectable and reviewable
// in source control as the durable artefacts they are.
const TEMPLATES_DIR  = path.join(__dirname, '..', '..', 'policy-templates');
const VALID_TEMPLATES = ['dev-default', 'strict', 'finance'];
const DEFAULT_TEMPLATE = 'dev-default';

function readTemplate(name) {
  return fs.readFileSync(path.join(TEMPLATES_DIR, `${name}.yml`), 'utf8');
}

// ── Starter file ───────────────────────────────────────────────────────────────

// STARTER_POLICY is the bytes of the default template (dev-default.yml). It
// is read once at module load so existing callers and tests that import
// `STARTER_POLICY` continue to see the same string contract. The same file
// is also addressable directly via readTemplate('dev-default').
const STARTER_POLICY = readTemplate(DEFAULT_TEMPLATE);

// ── ANSI colors ────────────────────────────────────────────────────────────────

const col = {
  r: s => `\x1b[31m${s}\x1b[0m`,
  g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`,
  c: s => `\x1b[36m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`,
  b: s => `\x1b[1m${s}\x1b[0m`,
};

// ── CLI ────────────────────────────────────────────────────────────────────────

/**
 * @param {string[]} args  Remaining CLI args after 'policy init'
 * @param {object}  [opts] { loader, fs } — injectable for tests
 * @returns {{ ok: boolean }}
 */
function runInitCli(args, opts = {}) {
  const loader = opts.loader || require('./loader');
  const fsMod  = opts.fs     || fs;

  const force      = (args || []).includes('--force');
  const fileArgIdx = (args || []).indexOf('--file');
  const filePath   = (fileArgIdx >= 0 && args[fileArgIdx + 1])
    ? path.resolve(args[fileArgIdx + 1])
    : loader.DEFAULT_PATH;

  // v0.6.6: --template <name> picks one of the shipped policy templates
  // under policy-templates/. Unknown names exit non-zero with the list of
  // valid names so the failure mode is self-explaining.
  const tplArgIdx  = (args || []).indexOf('--template');
  const templateName = (tplArgIdx >= 0 && args[tplArgIdx + 1])
    ? args[tplArgIdx + 1]
    : DEFAULT_TEMPLATE;

  console.log(col.b('\n⚡ Occasio — Policy Init\n'));

  if (!VALID_TEMPLATES.includes(templateName)) {
    console.log(col.r(`  Unknown template: "${templateName}"\n`));
    console.log(col.d('  Valid templates:'));
    for (const t of VALID_TEMPLATES) {
      const tag = t === DEFAULT_TEMPLATE ? col.d(' (default)') : '';
      console.log(`    ${col.c(t)}${tag}`);
    }
    console.log('');
    return { ok: false };
  }

  let templateBody;
  try {
    templateBody = readTemplate(templateName);
  } catch (e) {
    console.log(col.r(`  Could not read template "${templateName}": ${e.message}\n`));
    return { ok: false };
  }

  // Guard: refuse to overwrite without --force
  let exists = false;
  try { fsMod.statSync(filePath); exists = true; } catch {}

  if (exists && !force) {
    console.log(`  File:    ${filePath}  ${col.y('(already exists)')}\n`);
    console.log(col.y('  Policy file already exists — not overwriting.'));
    console.log(col.d('  Use --force to replace it, or edit the file directly.\n'));
    console.log(col.d('  Next steps:'));
    console.log(col.d(`    occasio policy show      — view the current policy`));
    console.log(col.d(`    occasio policy validate  — check it for errors`));
    console.log('');
    return { ok: false };
  }

  // Ensure parent directory exists
  try {
    fsMod.mkdirSync(path.dirname(filePath), { recursive: true });
  } catch (e) {
    console.log(col.r(`  Cannot create directory: ${e.message}\n`));
    return { ok: false };
  }

  // Write the starter file
  try {
    fsMod.writeFileSync(filePath, templateBody, 'utf8');
  } catch (e) {
    console.log(col.r(`  Cannot write file: ${e.message}\n`));
    return { ok: false };
  }

  const verb = (exists && force) ? 'Replaced' : 'Created';
  console.log(`  File:    ${col.g(filePath)}  ${col.g(`(${verb.toLowerCase()})`)}\n`);
  console.log(col.g(`  ✓  ${verb} ${templateName} policy.`));
  console.log(col.d('     The file references the published JSON Schema for IDE autocomplete.\n'));
  console.log(col.d('  Next steps:'));
  console.log(col.c(`    occasio policy show      — view the active policy with annotations`));
  console.log(col.c(`    occasio policy validate  — check the file for errors`));
  console.log('');
  return { ok: true };
}

module.exports = {
  runInitCli,
  STARTER_POLICY,
  // v0.6.6: exposed for tests and tooling that needs to enumerate or load
  // templates programmatically (e.g. the schema/template parity test).
  VALID_TEMPLATES,
  DEFAULT_TEMPLATE,
  TEMPLATES_DIR,
  readTemplate,
};
