#!/usr/bin/env python3
"""
verify_bundle.py — independent Python verifier for Occasio's single-file
evidence bundle (``run.occasio.json``, schema ``occasio-bundle/v1``).

Mirrors src/bundle/verify.js check-for-check, but written for an auditor
whose environment is Python-only and who refuses to trust Occasio's own
verifier to certify Occasio's own output. Everything is verified against
data embedded IN the bundle — the producer's absolute chain_file path is
never read.

Six checks, in order, fail-stop (each must pass):

    1. schema                 tag + required keys present, chain_slice non-empty
    2. manifest integrity     embedded artifacts hash to the manifest
    3. chain slice integrity  slice-mode chain walk, anchored to attestation
    4. policy binding         policy snapshot bytes == attestation.policy.file_hash
    5. git state matches chain attestation.subject.git_state == deriveGitState(slice)
    6. signature (optional)    Sigstore bundle valid + DSSE predicate matches

Strictness mirrors the Node ctx (lenient by default):

    --strict                  require signature AND policy binding AND git state
    --require-signature       an unsigned bundle fails check 6
    --require-policy-binding  policy.source=inferred / no snapshot fails check 4
    --require-git-state       a missing chain-sourced git_state fails check 5

Exit code 0 when every check passes, 1 otherwise.

Companion files in this directory (reused, kept byte-identical to their JS
counterparts so the schema is provably language-independent):
    audit_walker.py   _v8_json / canonical_serialize — V8 JSON.stringify
                      reproduction, used for the manifest hashes and the
                      per-row chain hash (NOT canonicalize, which sorts keys)
    canonicalize.py   RFC 8785 subset — used for predicate equivalence and
                      the git_state comparison (matches the JS canonicalize)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from canonicalize import canonicalize  # noqa: E402
import audit_walker  # noqa: E402

BUNDLE_SCHEMA = "occasio-bundle/v1"
PREDICATE_TYPE = "https://github.com/occasiolabs/occasio/spec/agent-attestation/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _v8_sha(value: Any) -> str:
    """sha256 over V8's JSON.stringify(value) — the exact form the JS
    manifest hashes use. Reuses the cross-language-tested serializer."""
    return hashlib.sha256(audit_walker.canonical_serialize(value)).hexdigest()


# ── ports of the JS helpers (byte-faithful) ──────────────────────────────────

def _git_state_from_row(row: dict) -> dict:
    """Mirror src/attest/index.js gitStateFromRow (fixed-key contract)."""
    t = (row or {}).get("tool_inputs") or {}
    return {
        "is_repo":         bool(t.get("is_repo")),
        "head":            t.get("head") or None,
        "branch":          t.get("branch") or None,
        "dirty":           bool(t.get("dirty")),
        "changed_files":   list(t["changed_files"]) if isinstance(t.get("changed_files"), list) else [],
        "untracked_files": list(t["untracked_files"]) if isinstance(t.get("untracked_files"), list) else [],
        "diff_hash":       t.get("diff_hash") or None,
        "digest":          t.get("digest") or None,
    }


def _derive_git_state(events: list) -> dict | None:
    """Mirror src/attest/index.js deriveGitState: first run_start, last run_end."""
    start = None
    end = None
    for e in (events or []):
        if not e or e.get("kind") != "git_state":
            continue
        phase = (e.get("tool_inputs") or {}).get("phase")
        if phase == "run_end":
            end = _git_state_from_row(e)        # last run_end wins
        elif not start:
            start = _git_state_from_row(e)       # first run_start wins
    if not start and not end:
        return None
    return {"provenance": "chain", "run_start": start, "run_end": end}


def _verify_slice(rows: list) -> dict:
    """Mirror src/audit/verifier.js verifySlice (slice mode: first row's
    prev_hash is unconstrained; internal continuity + per-row hash)."""
    errors = []
    if not isinstance(rows, list) or len(rows) == 0:
        return {"ok": False, "errors": [{"index": 0, "detail": "slice is empty"}],
                "first_hash": None, "last_hash": None, "chained": 0}
    first_hash = None
    last_hash = None
    chained = 0
    expected_prev = None
    for i, row in enumerate(rows):
        if not row or not isinstance(row.get("hash"), str) or len(row["hash"]) != 64:
            errors.append({"index": i, "detail": "row missing a valid 64-hex hash"})
            continue
        chained += 1
        stored = row["hash"]
        if expected_prev is None:
            first_hash = stored
        elif row.get("prev_hash") != expected_prev:
            errors.append({"index": i, "detail": "chain broken — prev_hash mismatch"})
        row_without_hash = {k: v for k, v in row.items() if k != "hash"}
        recomputed = hashlib.sha256(audit_walker.canonical_serialize(row_without_hash)).hexdigest()
        if recomputed != stored:
            errors.append({"index": i, "detail": "hash mismatch — row was modified"})
        last_hash = stored
        expected_prev = stored
    return {"ok": len(errors) == 0, "errors": errors,
            "first_hash": first_hash, "last_hash": last_hash, "chained": chained}


def _check_sigstore(sigstore_bundle: dict, attestation: dict) -> tuple[bool, str | None]:
    """Mirror src/bundle/verify.js #6: Sigstore verify + DSSE predicate match.
    Delegated to sigstore-python; if not installed, the check fails (the
    auditor installs it or accepts that the signature is unverified)."""
    try:
        from sigstore.verify import Verifier, policy  # type: ignore
        from sigstore.models import Bundle  # type: ignore
    except ImportError:
        return False, "sigstore-python not installed (pip install sigstore)"
    try:
        bundle_obj = Bundle.from_json(json.dumps(sigstore_bundle))
        Verifier.production().verify_dsse(bundle_obj, policy.UnsafeNoOp())
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)

    env = sigstore_bundle.get("dsseEnvelope") or {}
    if not env.get("payload"):
        return False, "sigstore_bundle missing dsseEnvelope.payload"
    if env.get("payloadType") != DSSE_PAYLOAD_TYPE:
        return False, f"unexpected payloadType: {env.get('payloadType')!r}"
    stmt = json.loads(base64.b64decode(env["payload"]))
    if stmt.get("predicateType") != PREDICATE_TYPE:
        return False, f"unexpected predicateType: {stmt.get('predicateType')!r}"
    expected = {k: v for k, v in attestation.items() if k != "signature"}
    if canonicalize(stmt.get("predicate")) != canonicalize(expected):
        return False, "signed predicate differs from embedded attestation"
    return True, None


# ── the verifier ─────────────────────────────────────────────────────────────

def verify_bundle(path: str, *, require_signature: bool = False,
                  require_policy_binding: bool = False,
                  require_git_state: bool = False) -> dict:
    checks = []

    def fail(name: str, detail: str) -> dict:
        checks.append({"name": name, "ok": False, "detail": detail})
        return {"ok": False, "checks": checks}

    # 1. read + schema
    try:
        with open(path, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        return fail("read bundle", str(exc))
    if bundle.get("schema") != BUNDLE_SCHEMA:
        return fail("schema", f"unexpected schema (want {BUNDLE_SCHEMA}, got {bundle.get('schema')})")
    required = ["run_id", "attestation", "chain_slice", "policy_snapshot", "manifest"]
    missing = [k for k in required if k not in bundle]
    if missing:
        return fail("schema", f"missing keys: {', '.join(missing)}")
    if not isinstance(bundle.get("chain_slice"), list) or len(bundle["chain_slice"]) == 0:
        return fail("schema", "chain_slice is empty")
    checks.append({"name": "schema", "ok": True, "detail": BUNDLE_SCHEMA})

    att = bundle["attestation"]
    man = bundle.get("manifest") or {}

    # 2. manifest integrity
    att_sha = _v8_sha(att)
    slice_sha = _v8_sha(bundle["chain_slice"])
    pol_text = (bundle.get("policy_snapshot") or {}).get("text")
    pol_sha = None if pol_text is None else _sha256_hex(pol_text)
    if att_sha != man.get("attestation_sha256"):
        return fail("manifest integrity", "attestation hash mismatch (bundle was modified)")
    if slice_sha != man.get("chain_slice_sha256"):
        return fail("manifest integrity", "chain_slice hash mismatch (bundle was modified)")
    if pol_sha != man.get("policy_sha256"):
        return fail("manifest integrity", "policy_snapshot hash mismatch (bundle was modified)")
    expect_digest = _v8_sha({
        "schema": BUNDLE_SCHEMA, "run_id": bundle["run_id"],
        "attestation_sha256": man.get("attestation_sha256"),
        "chain_slice_sha256": man.get("chain_slice_sha256"),
        "policy_sha256": man.get("policy_sha256"),
    })
    if expect_digest != man.get("bundle_digest"):
        return fail("manifest integrity", "bundle_digest mismatch")
    checks.append({"name": "manifest integrity", "ok": True, "detail": f"digest {str(man.get('bundle_digest'))[:16]}…"})

    # 3. chain slice integrity
    res = _verify_slice(bundle["chain_slice"])
    if not res["ok"]:
        detail = "; ".join(f"row {e['index']}: {e['detail']}" for e in res["errors"])
        return fail("chain slice integrity", f"slice broken: {detail}")
    ac = att.get("audit_chain")
    if not ac:
        return fail("chain slice integrity", "attestation missing audit_chain")
    if res["first_hash"] != ac.get("first_hash"):
        return fail("chain slice integrity", "slice first_hash does not match attestation")
    if res["last_hash"] != ac.get("last_hash"):
        return fail("chain slice integrity", "slice last_hash does not match attestation")
    checks.append({"name": "chain slice integrity", "ok": True,
                   "detail": f"{res['chained']} rows, anchored to attestation"})

    # 4. policy binding
    pol = att.get("policy")
    snap = bundle.get("policy_snapshot")
    if pol and pol.get("source") != "inferred" and snap and snap.get("text") is not None:
        snap_sha = _sha256_hex(snap["text"])
        if snap_sha != pol.get("file_hash"):
            return fail("policy binding", "policy snapshot bytes do not match attestation.policy.file_hash (policy swap)")
        checks.append({"name": "policy binding", "ok": True, "detail": f"policy {snap_sha[:12]}…"})
    elif require_policy_binding:
        return fail("policy binding",
                    "required (--require-policy-binding) but policy.source=inferred — no committed policy bytes to bind"
                    if pol and pol.get("source") == "inferred"
                    else "required (--require-policy-binding) but bundle carries no policy snapshot")
    else:
        detail = ("skipped (policy.source=inferred — weaker evidence)"
                  if pol and pol.get("source") == "inferred" else "skipped (no policy snapshot)")
        checks.append({"name": "policy binding", "ok": True, "detail": detail})

    # 5. git state matches chain
    claimed = (att.get("subject") or {}).get("git_state")
    if claimed and claimed.get("provenance") == "chain":
        rederived = _derive_git_state(bundle["chain_slice"])
        if not rederived:
            return fail("git state matches chain", "attestation claims chain-sourced git_state but slice has no git_state rows")
        if canonicalize(rederived) != canonicalize(claimed):
            return fail("git state matches chain", "subject.git_state differs from git_state recorded in the embedded slice")
        def _fp(s):
            return s["head"][:12] if (s and s.get("head")) else ("no-head" if s else "—")
        checks.append({"name": "git state matches chain", "ok": True,
                       "detail": f"run_start {_fp(rederived.get('run_start'))} · run_end {_fp(rederived.get('run_end'))}"})
    elif require_git_state:
        return fail("git state matches chain",
                    "required (--require-git-state) but attestation carries no chain-sourced git_state")

    # 6. signature (optional)
    sig = bundle.get("sigstore_bundle")
    if sig:
        ok, detail = _check_sigstore(sig, att)
        if not ok:
            return fail("signature", detail or "signature verification failed")
        checks.append({"name": "signature", "ok": True, "detail": "sigstore-verified"})
    elif require_signature:
        return fail("signature", "required (--require-signature) but bundle is unsigned")
    else:
        checks.append({"name": "signature", "ok": True, "detail": "unsigned bundle (no signature to verify)"})

    return {"ok": all(c["ok"] for c in checks), "checks": checks}


def _render(result: dict, strict: bool) -> int:
    for c in result["checks"]:
        mark = "OK" if c["ok"] else "FAIL"
        line = f"  [{mark:>4}] {c['name']}"
        if c.get("detail"):
            line += f"  ({c['detail']})"
        print(line)
    print()
    print(("PASS" if result["ok"] else "FAIL") + (" (strict)" if strict else ""))
    return 0 if result["ok"] else 1


def main() -> int:
    p = argparse.ArgumentParser(description="Independent Python verifier for an Occasio evidence bundle (occasio-bundle/v1).")
    p.add_argument("bundle", help="Path to run.occasio.json")
    p.add_argument("--strict", action="store_true", help="require signature AND policy binding AND git state")
    p.add_argument("--require-signature", action="store_true")
    p.add_argument("--require-policy-binding", action="store_true")
    p.add_argument("--require-git-state", action="store_true")
    p.add_argument("--json", action="store_true", help="emit JSON result instead of human-readable lines")
    args = p.parse_args()

    result = verify_bundle(
        args.bundle,
        require_signature=args.strict or args.require_signature,
        require_policy_binding=args.strict or args.require_policy_binding,
        require_git_state=args.strict or args.require_git_state,
    )
    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1
    return _render(result, args.strict)


if __name__ == "__main__":
    sys.exit(main())
