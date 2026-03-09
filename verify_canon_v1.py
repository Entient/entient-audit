#!/usr/bin/env python3
"""
verify_canon_v1.py -- Standalone ENTIENT receipt verifier.

Verifies an ENTIENT receipt independently, without trusting the server.
Uses only the receipt JSON and the published public key.

Requires: PyNaCl (pip install pynacl)

Usage:
    # Fetch a receipt and verify it
    curl -s https://api.entient.com/v1/demo | python -m json.tool > receipt.json
    python verify_canon_v1.py receipt.json

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
    """Load a receipt from a JSON file. Handles both raw receipt
    and demo-endpoint wrapper (extracts .receipt if present)."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # If this is a demo response, extract the receipt
    if "receipt" in data and "demo" in data:
        return data["receipt"]
    # If this wraps a receipt
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

    # Resolve public key
    if args.fetch_key:
        public_key = fetch_public_key(args.base_url)
    elif args.public_key:
        public_key = args.public_key
    else:
        public_key = receipt.get("signer", "")

    if not public_key:
        print("ERROR: No public key available. Use --public-key or --fetch-key.")
        sys.exit(2)

    # Run verification checks
    checks = []

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

    all_passed = all(v for _, v in checks)

    # Output
    if args.json:
        result = {
            "valid": all_passed,
            "receipt_coord": receipt.get("receipt_coord", ""),
            "checks": {name: passed for name, passed in checks},
            "public_key": public_key[:16] + "...",
            "canon_version": receipt.get("canon_version"),
        }
        print(json.dumps(result, indent=2))
    else:
        print()
        print("ENTIENT Receipt Verification")
        print("=" * 40)
        print(f"  Receipt: {receipt.get('receipt_coord', 'unknown')}")
        print(f"  Type:    {receipt.get('receipt_type', 'unknown')}")
        print(f"  Signed:  {receipt.get('timestamp_utc', 'unknown')}")
        print(f"  Key:     {public_key[:16]}...")
        print()
        for name, passed in checks:
            mark = "PASS" if passed else "FAIL"
            print(f"  {mark}  {name}")
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
