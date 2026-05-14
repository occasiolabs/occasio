#!/usr/bin/env python3
"""
attest_verify.py — independent Python verifier for Occasio's
AI-Agent Behavioral Attestation v1 predicate.

Mirrors src/attest/verify.js, but written for an auditor whose
environment is Python-only and who refuses to trust Occasio's
own verifier to certify Occasio's own output. Three independent
checks, in order, each must pass:

    1. Sigstore signature  (Fulcio cert chain + Rekor inclusion)
    2. DSSE payload ↔ attestation predicate canonical-byte equivalence
    3. Audit-chain integrity end-to-end + first/last hash containment

Step 1 is delegated to ``sigstore-python`` when available. When the
library is not installed the step is marked "skipped (install
sigstore-python)" rather than silently passing; the auditor decides
whether to install it or to accept a partial verification.

Usage::

    python3 attest_verify.py <attestation.json> [--bundle <path>]
                             [--chain <path>]

Exit code 0 when every (non-skipped) check passes, 1 otherwise.

Companion files in this directory:
    canonicalize.py   RFC 8785 subset (kept in lockstep with the
                      Node and browser implementations)
    audit_walker.py   the audit-chain walker, reused for step 3
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from typing import Any

# Allow `import canonicalize` / `import audit_walker` when invoked
# directly from this folder.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from canonicalize import canonicalize  # noqa: E402
import audit_walker  # noqa: E402

PREDICATE_TYPE = (
    "https://github.com/occasiolabs/occasio/spec/agent-attestation/v1"
)
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _check_sigstore(bundle: dict) -> tuple[bool, str | None, str]:
    """Try to verify the Sigstore bundle. Returns (passed, detail, note).

    ``note`` is one of: 'verified', 'skipped', or an error string.
    The auditor can decide whether to treat a 'skipped' as a failure.
    """
    try:
        from sigstore.verify import Verifier, policy  # type: ignore
        from sigstore.models import Bundle  # type: ignore
    except ImportError:
        return (
            False,
            "sigstore-python not installed (pip install sigstore)",
            "skipped",
        )

    try:
        bundle_obj = Bundle.from_json(json.dumps(bundle))
        verifier = Verifier.production()
        # We do not pin the identity here — the auditor's policy may
        # require workflow-ref pinning. For the reference verifier we
        # accept any Fulcio cert and let the audit-chain step bind
        # the predicate to a concrete run_id.
        verifier.verify_dsse(bundle_obj, policy.UnsafeNoOp())
        return True, None, "verified"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc), "error"


def _check_payload_equivalence(
    attestation: dict, bundle: dict
) -> tuple[bool, str | None]:
    env = bundle.get("dsseEnvelope") or bundle.get("dsse_envelope")
    if not env or not env.get("payload"):
        return False, "bundle missing dsseEnvelope.payload"
    if env.get("payloadType") != DSSE_PAYLOAD_TYPE:
        return False, f"unexpected payloadType: {env.get('payloadType')!r}"

    try:
        payload_bytes = base64.b64decode(env["payload"])
        statement = json.loads(payload_bytes)
    except Exception as exc:  # noqa: BLE001
        return False, f"cannot decode DSSE payload: {exc}"

    if statement.get("predicateType") != PREDICATE_TYPE:
        return False, f"unexpected predicateType: {statement.get('predicateType')!r}"

    expected = {k: v for k, v in attestation.items() if k != "signature"}
    if canonicalize(statement.get("predicate")) != canonicalize(expected):
        return False, "predicate differs from DSSE payload predicate"
    return True, None


def _check_audit_chain(
    attestation: dict, chain_path: str | None
) -> tuple[bool, str | None]:
    chain_file = chain_path or attestation.get("audit_chain", {}).get("chain_file")
    if not chain_file:
        return False, "no chain_file in attestation and --chain not provided"
    if not os.path.exists(chain_file):
        return False, f"chain file not found: {chain_file}"

    # audit_walker exits 0/1 based on integrity; reuse its internals
    # to also capture the first/last hash positions.
    first_target = attestation.get("audit_chain", {}).get("first_hash")
    last_target = attestation.get("audit_chain", {}).get("last_hash")
    if not first_target or not last_target:
        return False, "attestation missing first_hash/last_hash"

    prev = audit_walker.GENESIS
    chained = 0
    first_idx = -1
    last_idx = -1
    with open(chain_file, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            if not line:
                continue
            row = json.loads(line)
            stored = row.pop("hash", None)
            if not isinstance(stored, str) or len(stored) != 64:
                continue
            if row.get("prev_hash") != prev:
                return False, f"chain broken at line {lineno}"
            recomputed = audit_walker.hashlib.sha256(
                audit_walker.canonical_serialize(row)
            ).hexdigest()
            if recomputed != stored:
                return False, f"hash mismatch at line {lineno}"
            prev = stored
            chained += 1
            if stored == first_target and first_idx == -1:
                first_idx = lineno
            if stored == last_target:
                last_idx = lineno

    if first_idx == -1:
        return False, "first_hash not found in chain"
    if last_idx == -1:
        return False, "last_hash not found in chain"
    if last_idx < first_idx:
        return False, "last_hash precedes first_hash in chain"
    return True, f"chain_length={chained}, slice rows {first_idx}..{last_idx}"


def verify(
    attestation_path: str,
    bundle_path: str | None = None,
    chain_path: str | None = None,
) -> dict:
    """Run all three checks and return a structured result."""
    if not bundle_path:
        if attestation_path.endswith(".json"):
            bundle_path = attestation_path[:-5] + ".sigstore.json"
        else:
            bundle_path = attestation_path + ".sigstore.json"

    attestation = _read_json(attestation_path)
    if not os.path.exists(bundle_path):
        # An unsigned attestation is still verifiable for the payload
        # equivalence and chain steps — surface that as 'skipped' on
        # step 1 rather than erroring out.
        bundle = None
    else:
        bundle = _read_json(bundle_path)

    checks = []

    if bundle is None:
        checks.append({
            "name": "sigstore signature",
            "ok": False,
            "note": "skipped",
            "detail": "no Sigstore bundle file alongside attestation",
        })
    else:
        ok, detail, note = _check_sigstore(bundle)
        checks.append({
            "name": "sigstore signature",
            "ok": ok,
            "note": note,
            "detail": detail,
        })

    if bundle is None:
        checks.append({
            "name": "bundle payload matches attestation",
            "ok": False,
            "note": "skipped",
            "detail": "no bundle to compare against",
        })
    else:
        ok, detail = _check_payload_equivalence(attestation, bundle)
        checks.append({
            "name": "bundle payload matches attestation",
            "ok": ok,
            "note": "verified" if ok else "failed",
            "detail": detail,
        })

    ok, detail = _check_audit_chain(attestation, chain_path)
    checks.append({
        "name": "audit chain integrity",
        "ok": ok,
        "note": "verified" if ok else "failed",
        "detail": detail,
    })

    # Overall pass: every check is ok=True. Skipped counts as not-ok
    # so the caller cannot pretend a partial verification was a full
    # one. The detail line tells the auditor what to install to lift
    # the skip.
    overall = all(c["ok"] for c in checks)
    return {"ok": overall, "checks": checks}


def _render(result: dict) -> int:
    for c in result["checks"]:
        mark = "OK" if c["ok"] else ("SKIP" if c["note"] == "skipped" else "FAIL")
        line = f"  [{mark:>4}] {c['name']}"
        if c.get("detail"):
            line += f"  ({c['detail']})"
        print(line)
    print()
    print("PASS" if result["ok"] else "FAIL")
    return 0 if result["ok"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Independent Python verifier for Occasio Agent Attestation v1."
        )
    )
    parser.add_argument("attestation", help="Path to attestation.json")
    parser.add_argument(
        "--bundle",
        help=(
            "Path to Sigstore bundle (default: <attestation>.sigstore.json)"
        ),
    )
    parser.add_argument(
        "--chain",
        help=(
            "Path to audit chain file. Default: read chain_file from the "
            "attestation."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON result instead of human-readable lines.",
    )
    args = parser.parse_args()

    result = verify(args.attestation, args.bundle, args.chain)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1
    return _render(result)


if __name__ == "__main__":
    sys.exit(main())
