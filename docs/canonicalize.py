"""
canonicalize.py — RFC 8785 subset for byte-stable JSON serialisation.

Companion to docs/audit_walker.py and docs/attest_verify.py: lets an
auditor in a Python-only environment re-verify a LocalFirst
attestation against the producer's canonical form without trusting
the producer's code.

Must stay logically identical to src/attest/canonicalize.js and the
inline copy in integrations/attest-view/viewer.js. The three
implementations exist so the schema is provably language-independent;
diverging them defeats the point.

Deviations from strict RFC 8785 (documented, intentional):
    - Floats use Python's json.dumps form. RFC 8785 mandates a
      specific ECMAScript Number.prototype.toString form which is
      equivalent for integers and most finite floats but not formally
      identical across all edge cases. The agent-attestation v1
      schema contains only integer counts and string hashes, so the
      distinction does not bite there.
    - Lone-surrogate handling matches Python json.dumps (escapes
      via \\uXXXX). JCS specifies the same.
"""

from __future__ import annotations

import json
from typing import Any


def canonicalize(value: Any) -> str:
    """Return the canonical-JSON string for ``value``.

    Rules:
      - object keys sorted lexicographically by UTF-16 code unit
        (Python's default ``sorted`` on strs is UTF-16-equivalent for
        the BMP, which covers every key in the v1 schema)
      - ``None`` ``True`` ``False`` map to ``null``/``true``/``false``
      - object members whose value is ``None`` are kept (they encode
        explicit nullable fields like ``policy.version``); members
        absent from the dict are not invented
      - arrays preserve order
      - rejects ``float('nan')``/``inf``, callables, types,
        non-string keys

    Raises ``ValueError`` on rejected inputs.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("canonicalize: non-finite number")
        # json.dumps for floats matches what V8's JSON.stringify
        # produces for finite floats in practice. For the v1 schema
        # this codepath is unused; kept for completeness.
        return json.dumps(value)
    if isinstance(value, str):
        # json.dumps emits a fully-escaped RFC 8259 string. Matches
        # what V8's JSON.stringify does for ASCII + most Unicode.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value.keys():
            if not isinstance(k, str):
                raise ValueError(
                    f"canonicalize: non-string key {k!r}"
                )
        items = sorted(value.items(), key=lambda kv: kv[0])
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonicalize(v)
            for k, v in items
        ) + "}"
    raise ValueError(f"canonicalize: unsupported type {type(value).__name__}")
