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
 *   - numbers must be integers (see below); JSON.stringify form is used
 *   - strings use V8's JSON.stringify escaping
 *   - rejects: undefined at top level, non-finite numbers, NON-INTEGER
 *     numbers (see below), functions, symbols
 *
 * Why non-integer numbers are rejected (enforced cross-language invariant)
 *   JavaScript has a single `number` type. JSON.parse('1.0') yields the
 *   integer 1; JSON.stringify(1) emits '1'. Python distinguishes int from
 *   float: json.loads('1.0') yields float(1.0); json.dumps(1.0) emits
 *   '1.0'. If we silently accepted floats, the JS verifier and the Python
 *   verifier would canonicalize the same JSON file to different bytes —
 *   silent byte-equivalence breakage and the schema is no longer language-
 *   independent. We reject non-integer numbers explicitly on both sides,
 *   matching error messages, so the failure mode is loud and identical.
 *
 *   Integer-valued floats (1.0 parsed by Python as float(1.0)) ARE
 *   accepted: both implementations coerce to the integer representation
 *   so a round-trip through either side produces the same canonical bytes.
 *
 *   If a future schema requires decimal precision (it should not — counts
 *   and timestamps don't need it), encode as a string ("1.5") and parse
 *   numerically in the consumer. The canonicalize boundary stays integer-
 *   only.
 *
 * Where this deviates from strict RFC 8785:
 *   - Float serialisation: RFC 8785 mandates a specific ECMAScript form
 *     for non-integer floats. We sidestep this entirely by rejecting them
 *     above. The deviation is intentional and load-bearing for cross-
 *     language byte-equivalence; remove it only when adopting a vetted JCS
 *     library that handles ECMAScript Number.prototype.toString exactly.
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
      if (!Number.isInteger(value)) {
        // See the header comment "Why non-integer numbers are rejected".
        // If you hit this, encode the field as a string in the schema
        // instead of changing this guard.
        throw new Error(
          'canonicalize: non-integer number ' + value +
          ' — cross-language byte-equivalence requires schema fields be ' +
          'integers or strings. Encode decimal values as strings.'
        );
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
