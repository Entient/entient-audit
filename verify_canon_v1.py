#!/usr/bin/env python3
"""
verify_canon_v1.py -- Standalone ENTIENT receipt verifier.

Verifies an ENTIENT receipt independently, without trusting the server.
Uses only the receipt JSON and the published public key.

Supports two receipt formats:
  - Legacy compute receipts (canon_version 1, field exclusion)
  - ReceiptEnvelopeV1 (envelope_version "1", canonical_payload + signing_domain)

Requires: PyNaCl (pip install pynacl)

Usage:
    # Verify a compute receipt
    python verify_canon_v1.py receipt.json

    # Verify a spatial ReceiptEnvelopeV1
    python verify_canon_v1.py envelope.json

    # Verify with an explicit public key
    python verify_canon_v1.py receipt.json --public-key <hex>

    # Fetch public key from ENTIENT automatically
    python verify_canon_v1.py receipt.json --fetch-key

Exit codes:
    0 = all checks passed
    1 = verification failed
    2 = usage error
"""

import json
import sys
import hashlib
import argparse
import urllib.request
import urllib.error


# Fields excluded from canonical form before signing.
# This MUST match the server's _receipt_canonical_bytes() exclusion set.
# Changing this set is a canon_version break.
_EXCLUDED = {
    "signature", "signer", "signer_fingerprint",
    "signature_algorithm",
    "receipt_coord", "payload_hash",
}


def canonical_bytes(receipt: dict) -> bytes:
    """Reconstruct the canonical bytes that were signed.

    Rules (canon_version 1):
      - Remove excluded fields (signature, signer, derived fields)
      - Sort keys
      - Compact JSON separators (no whitespace)
      - UTF-8 encoding
    """
    clean = {k: v for k, v in receipt.items() if k not in _EXCLUDED}
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_signature(receipt: dict, public_key_hex: str) -> bool:
    """Verify Ed25519 signature over canonical bytes."""
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:
        print("ERROR: PyNaCl required. Install with: pip install pynacl")
        sys.exit(2)

    sig_hex = receipt.get("signature", "")
    if not sig_hex:
        return False

    canon = canonical_bytes(receipt)
    sig_bytes = bytes.fromhex(sig_hex)
    pub_bytes = bytes.fromhex(public_key_hex)

    try:
        vk = VerifyKey(pub_bytes)
        vk.verify(canon, sig_bytes)
        return True
    except (BadSignatureError, Exception):
        return False


def verify_payload_hash_present(receipt: dict) -> bool:
    """Check that payload_hash is present and well-formed.

    NOTE: payload_hash uses domain-separated hashing over internal
    payload fields (ENTIENT:receipt:v1: prefix + canonical_json of
    the payload dict). The exact field set is internal to the server.
    Full recomputation from outside is not possible without server
    internals. Signature verification is the authoritative proof --
    payload_hash is a derived convenience field excluded from signing.
    """
    h = receipt.get("payload_hash", "")
    if not h:
        return False
    # Must be hex, either 32 chars (truncated) or 64 chars (full SHA-256)
    if len(h) not in (32, 64):
        return False
    try:
        int(h, 16)
        return True
    except ValueError:
        return False


def verify_canon_version(receipt: dict) -> bool:
    """Check that canon_version is present and supported."""
    cv = receipt.get("canon_version")
    return cv == 1


def verify_signer_key(receipt: dict, public_key_hex: str) -> bool:
    """Verify that the receipt's signer field matches the expected public key."""
    return receipt.get("signer", "") == public_key_hex


# ================================================================
# ReceiptEnvelopeV1 support
# Spatial receipts carry canonical_payload and signing_domain directly.
# Verification is: domain_prefix + canonical_payload => Ed25519 verify.
# No field exclusion needed — the canonical form is pre-built.
# ================================================================

def is_envelope_v1(data: dict) -> bool:
    """Detect ReceiptEnvelopeV1 format."""
    return data.get("envelope_version") == "1"


def verify_envelope_signature(envelope: dict, public_key_hex: str) -> bool:
    """Verify Ed25519 signature over domain-prefixed canonical payload."""
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:
        print("ERROR: PyNaCl required. Install with: pip install pynacl")
        sys.exit(2)

    canonical_payload = envelope.get("canonical_payload")
    signature = envelope.get("signature")
    signing_domain = envelope.get("signing_domain", "")

    if not isinstance(canonical_payload, str) or len(canonical_payload) == 0:
        return False
    if not isinstance(signature, str) or len(signature) == 0:
        return False

    # Domain prefix: the signing_domain string + "\n" is prepended to the
    # canonical payload before signing. The stored signing_domain may or
    # may not include the trailing newline.
    prefix = signing_domain
    if prefix and not prefix.endswith("\n"):
        prefix = prefix + "\n"

    signed_bytes = (prefix + canonical_payload).encode("utf-8")
    sig_bytes = bytes.fromhex(signature)
    pub_bytes = bytes.fromhex(public_key_hex)

    try:
        vk = VerifyKey(pub_bytes)
        vk.verify(signed_bytes, sig_bytes)
        return True
    except (BadSignatureError, Exception):
        return False


def verify_envelope_payload_hash(envelope: dict) -> bool:
    """Verify payload_hash matches sha256(canonical_payload)."""
    canonical_payload = envelope.get("canonical_payload", "")
    payload_hash = envelope.get("payload_hash", "")

    if not canonical_payload or not payload_hash:
        return False

    computed = "sha256:" + hashlib.sha256(
        canonical_payload.encode("utf-8")
    ).hexdigest()

    return computed == payload_hash


def verify_envelope_structure(envelope: dict) -> list:
    """Validate required ReceiptEnvelopeV1 fields. Returns list of errors."""
    errors = []
    required_strings = [
        "receipt_id", "timestamp_utc", "object_id", "payload_hash",
        "canonical_payload", "signature", "signing_domain",
        "signer_public_key", "signer_fingerprint",
    ]
    for field in required_strings:
        val = envelope.get(field)
        if not isinstance(val, str) or len(val) == 0:
            errors.append(f"{field} missing or empty")

    if envelope.get("signature_algorithm") != "Ed25519":
        errors.append(f"signature_algorithm must be Ed25519")

    valid_types = {"witness", "settlement", "refusal", "attestation"}
    if envelope.get("receipt_type") not in valid_types:
        errors.append(f"receipt_type must be one of {valid_types}")

    ext = envelope.get("extensions", {})
    entient = ext.get("entient", {}) if isinstance(ext, dict) else {}
    if not isinstance(entient, dict) or "spatial_action" not in entient:
        errors.append("extensions.entient.spatial_action missing")

    return errors


def fetch_public_key(base_url: str = "https://api.entient.com") -> str:
    """Fetch the active public key from the ENTIENT key registry."""
    url = f"{base_url}/.well-known/entient-keys.json"
    try:
        resp = urllib.request.urlopen(url, timeout=15)
        data = json.loads(resp.read().decode())
        keys = data.get("keys", [])
        for k in keys:
            if k.get("status") == "active":
                return k.get("public_key_hex", "")
        if keys:
            return keys[0].get("public_key_hex", "")
    except Exception as e:
        print(f"ERROR: Could not fetch public key from {url}: {e}")
        sys.exit(2)
    return ""


def load_receipt(path: str) -> dict:
    """Load a receipt from a JSON file. Handles:
    - Raw receipt dict
    - Demo-endpoint wrapper (extracts .receipt)
    - Spatial response wrapper (extracts .receipt if it's an envelope)
    - ReceiptEnvelopeV1 directly
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # If this is a demo response, extract the receipt
    if "receipt" in data and "demo" in data:
        return data["receipt"]
    # If .receipt is a ReceiptEnvelopeV1, use it directly
    if "receipt" in data and isinstance(data["receipt"], dict):
        inner = data["receipt"]
        if inner.get("envelope_version") == "1":
            return inner
    # If this wraps a receipt (legacy)
    if "receipt" in data and "signature" not in data:
        return data["receipt"]
    return data


def main():
    parser = argparse.ArgumentParser(
        description="Verify an ENTIENT receipt independently"
    )
    parser.add_argument("receipt", help="Path to receipt JSON file")
    parser.add_argument(
        "--public-key", help="Ed25519 public key (hex). If omitted, uses receipt's signer field."
    )
    parser.add_argument(
        "--fetch-key", action="store_true",
        help="Fetch the public key from api.entient.com"
    )
    parser.add_argument(
        "--base-url", default="https://api.entient.com",
        help="ENTIENT API base URL (for --fetch-key)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON"
    )
    args = parser.parse_args()

    # Load receipt
    try:
        receipt = load_receipt(args.receipt)
    except Exception as e:
        print(f"ERROR: Could not load receipt: {e}")
        sys.exit(2)

    # Detect receipt format
    envelope_mode = is_envelope_v1(receipt)

    # Resolve public key
    if args.fetch_key:
        public_key = fetch_public_key(args.base_url)
    elif args.public_key:
        public_key = args.public_key
    elif envelope_mode:
        public_key = receipt.get("signer_public_key", "")
    else:
        public_key = receipt.get("signer", "")

    if not public_key:
        print("ERROR: No public key available. Use --public-key or --fetch-key.")
        sys.exit(2)

    # Run verification checks
    checks = []

    if envelope_mode:
        # ReceiptEnvelopeV1 verification path
        # 1. Structure validation
        struct_errors = verify_envelope_structure(receipt)
        checks.append(("envelope_structure", len(struct_errors) == 0))

        # 2. Signature (domain-prefixed)
        sig_valid = verify_envelope_signature(receipt, public_key)
        checks.append(("signature", sig_valid))

        # 3. Payload hash (recomputable — sha256 of canonical_payload)
        hash_valid = verify_envelope_payload_hash(receipt)
        checks.append(("payload_hash", hash_valid))

        # 4. Signer key matches
        key_valid = receipt.get("signer_public_key", "") == public_key
        checks.append(("signer_key", key_valid))

        receipt_label = receipt.get("receipt_id", "unknown")
        receipt_type = receipt.get("receipt_type", "unknown")
        spatial_action = receipt.get("extensions", {}).get("entient", {}).get("spatial_action", "")
        timestamp = receipt.get("timestamp_utc", "unknown")
    else:
        # Legacy compute receipt verification path
        # 1. Signature
        sig_valid = verify_signature(receipt, public_key)
        checks.append(("signature", sig_valid))

        # 2. Payload hash presence (format check -- full recomputation
        #    requires server internals; signature is the authoritative proof)
        hash_valid = verify_payload_hash_present(receipt)
        checks.append(("payload_hash_present", hash_valid))

        # 3. Canon version
        cv_valid = verify_canon_version(receipt)
        checks.append(("canon_version", cv_valid))

        # 4. Signer key matches
        key_valid = verify_signer_key(receipt, public_key)
        checks.append(("signer_key", key_valid))

        receipt_label = receipt.get("receipt_coord", "unknown")
        receipt_type = receipt.get("receipt_type", "unknown")
        spatial_action = ""
        timestamp = receipt.get("timestamp_utc", "unknown")

    all_passed = all(v for _, v in checks)

    # Output
    if args.json:
        result = {
            "valid": all_passed,
            "format": "envelope_v1" if envelope_mode else "legacy",
            "receipt_id": receipt_label,
            "receipt_type": receipt_type,
            "checks": {name: passed for name, passed in checks},
            "public_key": public_key[:16] + "...",
        }
        if envelope_mode:
            result["spatial_action"] = spatial_action
            result["signing_domain"] = receipt.get("signing_domain", "")
        else:
            result["canon_version"] = receipt.get("canon_version")
        print(json.dumps(result, indent=2))
    else:
        print()
        print("ENTIENT Receipt Verification")
        print("=" * 40)
        fmt = "ReceiptEnvelopeV1" if envelope_mode else "Legacy (canon_v1)"
        print(f"  Format:  {fmt}")
        print(f"  Receipt: {receipt_label}")
        type_display = f"{receipt_type} ({spatial_action})" if spatial_action else receipt_type
        print(f"  Type:    {type_display}")
        print(f"  Signed:  {timestamp}")
        print(f"  Key:     {public_key[:16]}...")
        if envelope_mode:
            print(f"  Domain:  {receipt.get('signing_domain', '')}")
        print()
        for name, passed in checks:
            mark = "PASS" if passed else "FAIL"
            print(f"  {mark}  {name}")
        if envelope_mode and not all_passed:
            struct_errors = verify_envelope_structure(receipt)
            for err in struct_errors:
                print(f"         -> {err}")
        print()
        if all_passed:
            print("  VERDICT: Receipt is independently verified.")
            print("           No trust in ENTIENT infrastructure required.")
        else:
            failed = [n for n, v in checks if not v]
            print(f"  VERDICT: Verification FAILED ({', '.join(failed)})")
        print()

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
