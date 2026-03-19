#!/usr/bin/env python3
"""
test_envelope_verify.py -- Cross-repo conformance tests for ReceiptEnvelopeV1.

Loads golden_fixtures.json (shared with entient-spatial) and verifies each
envelope using the audit verifier (verify_canon_v1.py).

Tests:
  - Each envelope verifies successfully (signature + payload_hash + structure)
  - Mutated payload rejected
  - Wrong domain rejected
  - Wrong signature rejected
  - Legacy non-envelope receipt still works
  - Envelope with missing fields rejected

Requires: PyNaCl (pip install pynacl)

Run: python test_envelope_verify.py
"""

import json
import sys
import os
import hashlib
import copy

# Import from the audit verifier
sys.path.insert(0, os.path.dirname(__file__))
from verify_canon_v1 import (
    is_envelope_v1,
    verify_envelope_signature,
    verify_envelope_payload_hash,
    verify_envelope_structure,
)

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "golden_fixtures.json")


def load_fixtures():
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test(name, passed):
    mark = "PASS" if passed else "FAIL"
    print(f"  {mark}  {name}")
    return passed


def main():
    fixtures = load_fixtures()
    public_key = fixtures["public_key_hex"]
    vectors = fixtures["vectors"]

    total = 0
    passed = 0

    print()
    print("ReceiptEnvelopeV1 — Audit Conformance Tests")
    print("=" * 50)
    print(f"  Fixtures: {FIXTURE_PATH}")
    print(f"  Public key: {public_key[:16]}...")
    print(f"  Vectors: {len(vectors)}")
    print()

    for vec in vectors:
        action = vec["action"]
        envelope = vec["envelope"]

        print(f"  [{action}]")

        # 1. Detected as envelope
        total += 1
        if test(f"{action}/is_envelope_v1", is_envelope_v1(envelope)):
            passed += 1

        # 2. Structure valid
        total += 1
        errors = verify_envelope_structure(envelope)
        if test(f"{action}/structure_valid ({len(errors)} errors)", len(errors) == 0):
            passed += 1
        else:
            for err in errors:
                print(f"           -> {err}")

        # 3. Signature valid
        total += 1
        if test(f"{action}/signature_valid", verify_envelope_signature(envelope, public_key)):
            passed += 1

        # 4. Payload hash valid
        total += 1
        if test(f"{action}/payload_hash_valid", verify_envelope_payload_hash(envelope)):
            passed += 1

        # 5. Mutated payload rejected
        total += 1
        mutated = copy.deepcopy(envelope)
        mutated["canonical_payload"] = mutated["canonical_payload"][:-2] + 'X}'
        if test(f"{action}/mutated_payload_rejected", not verify_envelope_signature(mutated, public_key)):
            passed += 1

        # 6. Wrong domain rejected
        total += 1
        wrong_domain = copy.deepcopy(envelope)
        # Swap forge<->transfer to get a different domain
        if "forge" in wrong_domain["signing_domain"]:
            wrong_domain["signing_domain"] = "ENTIENT:spatial:transfer:v1"
        else:
            wrong_domain["signing_domain"] = "ENTIENT:spatial:forge:v1"
        if test(f"{action}/wrong_domain_rejected", not verify_envelope_signature(wrong_domain, public_key)):
            passed += 1

        # 7. Wrong signature rejected
        total += 1
        bad_sig = copy.deepcopy(envelope)
        sig = bad_sig["signature"]
        bad_sig["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
        if test(f"{action}/wrong_signature_rejected", not verify_envelope_signature(bad_sig, public_key)):
            passed += 1

        # 8. Empty canonical_payload rejected
        total += 1
        empty_cp = copy.deepcopy(envelope)
        empty_cp["canonical_payload"] = ""
        if test(f"{action}/empty_payload_rejected", not verify_envelope_signature(empty_cp, public_key)):
            passed += 1

        print()

    # Legacy backward-compat test
    print("  [legacy]")
    legacy_receipt = {
        "coord": "sha256:abc123",
        "receipt_coord": "receipt:sha256:abc123",
        "canon_version": 1,
        "signer": public_key,
        "signature": "deadbeef",
        "payload_hash": "abcd1234abcd1234abcd1234abcd1234",
    }
    total += 1
    if test("legacy/not_detected_as_envelope", not is_envelope_v1(legacy_receipt)):
        passed += 1

    total += 1
    errors = verify_envelope_structure(legacy_receipt)
    if test("legacy/fails_envelope_structure", len(errors) > 0):
        passed += 1
    print()

    # Malformed envelope tests
    print("  [malformed]")
    total += 1
    missing_version = copy.deepcopy(vectors[0]["envelope"])
    del missing_version["envelope_version"]
    if test("malformed/missing_version_not_detected", not is_envelope_v1(missing_version)):
        passed += 1

    total += 1
    null_payload = copy.deepcopy(vectors[0]["envelope"])
    null_payload["canonical_payload"] = None
    if test("malformed/null_payload_rejected", not verify_envelope_signature(null_payload, public_key)):
        passed += 1

    total += 1
    null_sig = copy.deepcopy(vectors[0]["envelope"])
    null_sig["signature"] = None
    if test("malformed/null_signature_rejected", not verify_envelope_signature(null_sig, public_key)):
        passed += 1
    print()

    # Summary
    print("=" * 50)
    failed = total - passed
    if failed == 0:
        print(f"  {passed}/{total} passed. All checks green.")
    else:
        print(f"  {passed}/{total} passed. {failed} FAILED.")
    print()

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
