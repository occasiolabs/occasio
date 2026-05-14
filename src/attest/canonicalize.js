'use strict';

/**
 * canonicalize.js — deterministic JSON serialisation for predicate/payload
 * byte-equivalence comparisons.
 *
 * This is a pragmatic subset of RFC 8785 (JSON Canonicalization Scheme):
 *   - object keys sorted lexicographically (UTF-16 code units; equivalent to
 *     default Array.prototype.sort on strings)
 *   - keys whose value is `undefined` are omitted (matches JSON.stringify)
 *   - arrays preserve order; `undefined` elements become `null`
 *   - numbers use V8's JSON.stringify form (RFC 8259 compliant for integers
 *     and finite decimals — our schema only uses integers, so this is exact)
 *   - strings use V8's JSON.stringify escaping
 *   - rejects: undefined at top level, non-finite numbers, functions, symbols
 *
 * Where this deviates from strict RFC 8785:
 *   - Float serialisation: RFC 8785 mandates a specific ECMAScript
 *     `Number.prototype.toString` form for non-integer floats. JSON.stringify
 *     in V8 matches this in practice but is not formally guaranteed. Our
 *     schema (agent-attestation v1) contains only integer counts and string
 *     hashes, so this is not an issue today. If we ever add float fields,
 *     swap this for a vetted JCS library.
 *   - Lone surrogate handling: JSON.stringify produces \uXXXX escapes which
 *     are valid RFC 8259. JCS specifies the same. Identical in practice.
 *
 * Why a tiny in-tree implementation instead of a dependency:
 *   - Must run unchanged in three places: Node (sign/verify), GitHub Action
 *     (no extra npm install before this runs), and the browser viewer
 *     (no build step). A copy-paste-ready ~30 lines is the cheapest path
 *     to "same bytes everywhere".
 *
 * IMPORTANT: keep this function logically identical to the inline copy in
 * integrations/attest-view/viewer.js. Any change here must be mirrored there.
 */

function canonicalize(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('canonicalize: non-finite number');
      }
      return JSON.stringify(value);
    case 'string':
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return '[' + value.map(v =>
          canonicalize(v === undefined ? null : v)
        ).join(',') + ']';
      }
      const keys = Object.keys(value)
        .filter(k => value[k] !== undefined)
        .sort();
      return '{' + keys.map(k =>
        JSON.stringify(k) + ':' + canonicalize(value[k])
      ).join(',') + '}';
    }
    case 'undefined':
      throw new Error('canonicalize: undefined at top level');
    default:
      throw new Error('canonicalize: unsupported type ' + typeof value);
  }
}

module.exports = { canonicalize };
