#!/usr/bin/env python3
"""
verify_canon_v1.py -- Standalone ENTIENT receipt verifier.

Independent third-party verification of ENTIENT receipts.
No trust in ENTIENT infrastructure required -- only the receipt JSON
and a published public key.

This tool is the auditor's entry point. It answers one question:
  "Is this receipt authentic and untampered?"

It does NOT evaluate trust chain logic (closures, I/O integrity,
evaluator decisions). That is the core's job. This tool verifies
the cryptographic proof that the core produced.

Supports four receipt formats:
  - DSSE envelopes (dsse_envelope field, standard Dead Simple Signing Envelopes)
  - Legacy compute receipts (canon_version 1, field exclusion)
  - ReceiptEnvelopeV1 (envelope_version "1", canonical_payload + signing_domain)
  - Core trust chain receipts (seal:/ obligation: coordinates, Ed25519 domain separation)

Requires: PyNaCl (pip install pynacl)

Usage:
    # Verify any ENTIENT receipt
    python verify_canon_v1.py receipt.json

    # Verify with an explicit public key
    python verify_canon_v1.py receipt.json --public-key <hex>

    # Fetch public key from ENTIENT automatically
    python verify_canon_v1.py receipt.json --fetch-key

    # Output as JSON (for pipelines)
    python verify_canon_v1.py receipt.json --json

Exit codes:
    0 = all checks passed
    1 = verification failed
    2 = usage error
"""

import base64
import json
import re
import sys
import hashlib
import argparse
import urllib.request
import urllib.error


# ================================================================
# DSSE — Dead Simple Signing Envelopes
# ================================================================
# Standard: https://github.com/secure-systems-lab/dsse/blob/master/envelope.md
# Wire format: {"payloadType": str, "payload": base64url, "signatures": [...]}
# PAE: "DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload
# Signature: Ed25519 over PAE bytes. Payload: base64url(canonical_json(receipt_payload_dict))

ENTIENT_RECEIPT_PAYLOAD_TYPE = "application/vnd.entient.receipt.v1+json"


def _b64dec(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding."""
    pt = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(pt)).encode("ascii") + b" " + pt
        + b" "
        + str(len(payload)).encode("ascii") + b" " + payload
    )


def is_dsse_receipt(data: dict) -> bool:
    """Detect a DSSE-enveloped receipt (top-level or nested under dsse_envelope)."""
    if "dsse_envelope" in data:
        env = data["dsse_envelope"]
    else:
        env = data
    return (
        isinstance(env, dict)
        and "payloadType" in env
        and "payload" in env
        and "signatures" in env
    )


def _get_dsse_envelope(data: dict) -> dict:
    """Extract the DSSE envelope dict regardless of nesting."""
    return data.get("dsse_envelope", data)


def verify_dsse_signature(data: dict, public_key_hex: str) -> bool:
    """Verify Ed25519 signature in a DSSE envelope."""
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:
        print("ERROR: PyNaCl required. Install with: pip install pynacl")
        sys.exit(2)

    envelope = _get_dsse_envelope(data)
    try:
        payload_bytes = _b64dec(envelope["payload"])
        pae_bytes = _dsse_pae(envelope["payloadType"], payload_bytes)
        pub_bytes = bytes.fromhex(public_key_hex)
        vk = VerifyKey(pub_bytes)
        for entry in envelope.get("signatures", []):
            try:
                sig_bytes = _b64dec(entry["sig"])
                vk.verify(pae_bytes, sig_bytes)
                return True
            except BadSignatureError:
                continue
        return False
    except Exception:
        return False


def extract_dsse_payload(data: dict) -> dict:
    """Decode the JSON payload from a DSSE envelope."""
    envelope = _get_dsse_envelope(data)
    payload_bytes = _b64dec(envelope["payload"])
    return json.loads(payload_bytes.decode("utf-8"))


def dsse_keyid(data: dict) -> str:
    envelope = _get_dsse_envelope(data)
    sigs = envelope.get("signatures", [])
    return sigs[0].get("keyid", "") if sigs else ""


# ================================================================
# Coordinate formats
# ================================================================
# ENTIENT uses content-addressed coordinates in two formats:
#   Legacy:  sha256:<64hex>          (full hash)
#   Core:    seal:<32hex>            (receipt coordinates)
#            obligation:<32hex>      (obligation coordinates)
#
# All are deterministic hashes over canonical content.

_COORD_PATTERNS = {
    "seal": re.compile(r"^seal:[0-9a-f]{32}$"),
    "obligation": re.compile(r"^obligation:[0-9a-f]{32}$"),
    "sha256": re.compile(r"^sha256:[0-9a-f]{64}$"),
}


def parse_coordinate(coord: str) -> dict:
    """Parse an ENTIENT coordinate string.

    Returns:
        {"format": "seal"|"obligation"|"sha256"|"unknown",
         "hash": "<hex>", "valid": bool}
    """
    if not isinstance(coord, str):
        return {"format": "unknown", "hash": "", "valid": False}
    for fmt, pattern in _COORD_PATTERNS.items():
        if pattern.match(coord):
            return {"format": fmt, "hash": coord.split(":", 1)[1], "valid": True}
    # Legacy: bare 32 or 64 hex chars (no prefix)
    if re.match(r"^[0-9a-f]{32}$", coord) or re.match(r"^[0-9a-f]{64}$", coord):
        return {"format": "bare_hex", "hash": coord, "valid": True}
    return {"format": "unknown", "hash": coord, "valid": False}


def is_valid_coordinate(coord: str) -> bool:
    """Check if a string is a valid ENTIENT coordinate in any format."""
    return parse_coordinate(coord)["valid"]


# ================================================================
# Core trust chain receipt detection
# ================================================================
# Core receipts use seal:<32hex> coordinates and Ed25519 with domain
# separation (ENTIENT:<domain>:<version>). They may contain evaluator
# claims (closure_integrity_state, io_integrity_state) as payload
# fields. This verifier checks signatures, not evaluator logic.

def is_core_receipt(data: dict) -> bool:
    """Detect a core trust chain receipt (seal: coordinates)."""
    rc = data.get("receipt_coord", "")
    return isinstance(rc, str) and rc.startswith("seal:")


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

    Accepts all ENTIENT coordinate/hash formats:
      - Bare hex: 32 or 64 hex chars
      - Prefixed: sha256:<64hex>, seal:<32hex>, obligation:<32hex>

    NOTE: payload_hash uses domain-separated hashing over internal
    payload fields. The exact field set is internal to the server.
    Full recomputation from outside is not possible without server
    internals. Signature verification is the authoritative proof --
    payload_hash is a derived convenience field excluded from signing.
    """
    h = receipt.get("payload_hash", "")
    if not h:
        return False
    return is_valid_coordinate(h)


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

    # Receipt types: spatial (witness/settlement/refusal/attestation) and
    # core trust chain types (identity/delegation/invocation/evaluation/
    # emission/certificate/challenge/corroboration/attestation/etc.)
    valid_types = {
        # Spatial
        "witness", "settlement", "refusal", "attestation",
        # Core trust chain (verifiable payload types, not execution logic)
        "identity", "delegation", "acceptance", "invocation",
        "evaluation", "emission", "certificate", "recognition",
        "suppression", "evidence", "retrieval", "corroboration",
        "challenge", "challenge_response", "instruction", "output",
    }
    if envelope.get("receipt_type") not in valid_types:
        errors.append(f"receipt_type must be one of {sorted(valid_types)}")

    ext = envelope.get("extensions", {})
    entient = ext.get("entient", {}) if isinstance(ext, dict) else {}
    if not isinstance(entient, dict):
        errors.append("extensions.entient must be a dict")
    elif "spatial_action" not in entient and "receipt_type" not in entient:
        # Spatial envelopes require spatial_action; core envelopes use receipt_type
        errors.append("extensions.entient.spatial_action or extensions.entient.receipt_type required")

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


# ================================================================
# Evaluator claim extraction (informational, not execution)
# ================================================================
# Core trust chain receipts may contain evaluator-backed claims.
# This verifier surfaces them as informational context alongside
# the cryptographic verification result. It does NOT evaluate
# whether the claims are correct -- that is the core's job.

_EVALUATOR_CLAIM_FIELDS = {
    "closure_integrity_state",
    "closure_integrity_score",
    "io_integrity_state",
    "io_integrity_score",
    "evaluator_coord",
    "evaluator_role",
}


def _extract_evaluator_claims(data: dict) -> dict:
    """Extract evaluator claim fields from a receipt payload.

    Returns only recognized claim fields that are present.
    These are informational -- the signature proves the issuer
    attested to these values, but this tool does not validate
    the evaluation logic itself.
    """
    claims = {}
    for field in _EVALUATOR_CLAIM_FIELDS:
        if field in data:
            claims[field] = data[field]
    return claims


def load_receipt(path: str) -> dict:
    """Load a receipt from a JSON file. Handles:
    - Raw receipt dict (legacy, envelope, or core)
    - Demo-endpoint wrapper (extracts .receipt)
    - Spatial response wrapper (extracts .receipt if it's an envelope)
    - Core trust chain receipt (seal: coordinate)
    - ReceiptEnvelopeV1 directly
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # If this is a demo response, extract the receipt
    if "receipt" in data and "demo" in data:
        return data["receipt"]
    # If .receipt is a ReceiptEnvelopeV1 or core receipt, use it directly
    if "receipt" in data and isinstance(data["receipt"], dict):
        inner = data["receipt"]
        if inner.get("envelope_version") == "1":
            return inner
        if is_core_receipt(inner):
            return inner
    # If this wraps a receipt (legacy)
    if "receipt" in data and "signature" not in data:
        return data["receipt"]
    return data


def main():
    parser = argparse.ArgumentParser(
        description="Verify an ENTIENT receipt independently. "
        "This tool VERIFIES receipts -- it does not create, issue, or "
        "validate execution correctness. See BOUNDARY.md."
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

    # Detect receipt format (DSSE checked first — newest standard)
    dsse_mode = is_dsse_receipt(receipt)
    envelope_mode = not dsse_mode and is_envelope_v1(receipt)
    core_mode = not dsse_mode and not envelope_mode and is_core_receipt(receipt)

    # Resolve public key
    if args.fetch_key:
        public_key = fetch_public_key(args.base_url)
    elif args.public_key:
        public_key = args.public_key
    elif dsse_mode:
        # DSSE payloads carry signer_fingerprint (short ID), not the full public key hex.
        # There is no self-contained key in the envelope — caller must supply one explicitly.
        public_key = ""
    elif envelope_mode:
        public_key = receipt.get("signer_public_key", "")
    else:
        public_key = receipt.get("signer", "")

    if not public_key:
        print("ERROR: No public key available. Use --public-key or --fetch-key.")
        sys.exit(2)

    # Run verification checks
    checks = []

    # Evaluator claims (informational -- we verify the signature, not the logic)
    evaluator_claims = {}

    if dsse_mode:
        # DSSE envelope verification path
        # 1. Signature (Ed25519 over PAE bytes — standard DSSE)
        sig_valid = verify_dsse_signature(receipt, public_key)
        checks.append(("dsse_signature", sig_valid))

        # 2. payloadType must match ENTIENT receipt type
        envelope = _get_dsse_envelope(receipt)
        pt_valid = envelope.get("payloadType") == ENTIENT_RECEIPT_PAYLOAD_TYPE
        checks.append(("payload_type", pt_valid))

        # Decode payload for display / evaluator claims
        try:
            payload = extract_dsse_payload(receipt)
        except Exception:
            payload = {}

        keyid = dsse_keyid(receipt)
        receipt_label = payload.get("receipt_coord", keyid or "unknown")
        receipt_type = payload.get("receipt_type", "unknown")
        spatial_action = ""
        timestamp = payload.get("issued_at", payload.get("timestamp_utc", "unknown"))
        evaluator_claims = _extract_evaluator_claims(payload)

    elif envelope_mode:
        # ReceiptEnvelopeV1 verification path
        # 1. Structure validation
        struct_errors = verify_envelope_structure(receipt)
        checks.append(("envelope_structure", len(struct_errors) == 0))

        # 2. Signature (domain-prefixed)
        sig_valid = verify_envelope_signature(receipt, public_key)
        checks.append(("signature", sig_valid))

        # 3. Payload hash (recomputable -- sha256 of canonical_payload)
        hash_valid = verify_envelope_payload_hash(receipt)
        checks.append(("payload_hash", hash_valid))

        # 4. Signer key matches
        key_valid = receipt.get("signer_public_key", "") == public_key
        checks.append(("signer_key", key_valid))

        # 5. Coordinate format (if present)
        rid = receipt.get("receipt_id", "")
        if rid:
            checks.append(("coordinate_format", is_valid_coordinate(rid)))

        receipt_label = receipt.get("receipt_id", "unknown")
        receipt_type = receipt.get("receipt_type", "unknown")
        spatial_action = receipt.get("extensions", {}).get("entient", {}).get("spatial_action", "")
        timestamp = receipt.get("timestamp_utc", "unknown")

        # Extract evaluator claims if present in canonical_payload
        try:
            payload = json.loads(receipt.get("canonical_payload", "{}"))
            evaluator_claims = _extract_evaluator_claims(payload)
        except (json.JSONDecodeError, TypeError):
            pass

    elif core_mode:
        # Core trust chain receipt verification path
        # Uses same Ed25519 + field exclusion as legacy, but with seal: coordinates
        # 1. Signature
        sig_valid = verify_signature(receipt, public_key)
        checks.append(("signature", sig_valid))

        # 2. Payload hash format
        hash_valid = verify_payload_hash_present(receipt)
        checks.append(("payload_hash_format", hash_valid))

        # 3. Coordinate format (seal:<32hex>)
        coord = receipt.get("receipt_coord", "")
        coord_info = parse_coordinate(coord)
        checks.append(("coordinate_format", coord_info["valid"] and coord_info["format"] == "seal"))

        # 4. Signer key matches
        key_valid = verify_signer_key(receipt, public_key)
        checks.append(("signer_key", key_valid))

        receipt_label = receipt.get("receipt_coord", "unknown")
        receipt_type = receipt.get("receipt_type", "unknown")
        spatial_action = ""
        timestamp = receipt.get("timestamp_utc", "unknown")

        # Extract evaluator claims from receipt payload
        evaluator_claims = _extract_evaluator_claims(receipt)

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

    # Determine format label
    if dsse_mode:
        fmt_label = "dsse"
        fmt_display = "DSSE (Dead Simple Signing Envelope)"
    elif envelope_mode:
        fmt_label = "envelope_v1"
        fmt_display = "ReceiptEnvelopeV1"
    elif core_mode:
        fmt_label = "core"
        fmt_display = "Core Trust Chain"
    else:
        fmt_label = "legacy"
        fmt_display = "Legacy (canon_v1)"

    # Output
    if args.json:
        result = {
            "valid": all_passed,
            "format": fmt_label,
            "receipt_id": receipt_label,
            "receipt_type": receipt_type,
            "checks": {name: passed for name, passed in checks},
            "public_key": public_key[:16] + "...",
        }
        if dsse_mode:
            result["keyid"] = dsse_keyid(receipt)
            result["payload_type"] = _get_dsse_envelope(receipt).get("payloadType", "")
        elif envelope_mode:
            result["spatial_action"] = spatial_action
            result["signing_domain"] = receipt.get("signing_domain", "")
        elif core_mode:
            coord_info = parse_coordinate(receipt.get("receipt_coord", ""))
            result["coordinate"] = coord_info
        else:
            result["canon_version"] = receipt.get("canon_version")
        if evaluator_claims:
            result["evaluator_claims"] = evaluator_claims
        print(json.dumps(result, indent=2))
    else:
        print()
        print("ENTIENT Independent Receipt Verification")
        print("=" * 44)
        print(f"  Format:  {fmt_display}")
        print(f"  Receipt: {receipt_label}")
        type_display = f"{receipt_type} ({spatial_action})" if spatial_action else receipt_type
        print(f"  Type:    {type_display}")
        print(f"  Signed:  {timestamp}")
        print(f"  Key:     {public_key[:16]}...")
        if dsse_mode:
            print(f"  KeyID:   {dsse_keyid(receipt)}")
            print(f"  PType:   {_get_dsse_envelope(receipt).get('payloadType', '')}")
        if envelope_mode:
            print(f"  Domain:  {receipt.get('signing_domain', '')}")
        if core_mode:
            coord_info = parse_coordinate(receipt.get("receipt_coord", ""))
            print(f"  Coord:   {coord_info['format']}:{coord_info['hash'][:16]}...")
        print()
        for name, passed in checks:
            mark = "PASS" if passed else "FAIL"
            print(f"  {mark}  {name}")
        if envelope_mode and not all_passed:
            struct_errors = verify_envelope_structure(receipt)
            for err in struct_errors:
                print(f"         -> {err}")
        if evaluator_claims:
            print()
            print("  Evaluator claims (signed, not re-evaluated):")
            for k, v in evaluator_claims.items():
                print(f"    {k}: {v}")
        print()
        if all_passed:
            print("  VERDICT: Receipt is independently verified.")
            print("           No trust in ENTIENT infrastructure required.")
            print("           The signer attested to these contents.")
        else:
            failed = [n for n, v in checks if not v]
            print(f"  VERDICT: Verification FAILED ({', '.join(failed)})")
        print()

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
