"""
receipts.py — Auditor-grade DSSE receipt signing and verification.

Produces DSSE (Dead Simple Signing Envelope) signed receipts per
https://github.com/secure-systems-lab/dsse/blob/master/envelope.md

Trust model:
  - ReceiptSigner signs using a key resolved by keyid from a KeyRegistry
  - ReceiptVerifier verifies using ONLY the envelope's keyid + a KeyRegistry
    (no access to private key material required for ECDSA)
  - KeyRegistry can be exported as public-only for independent verifiers

Envelope structure:
{
    "payloadType": "<media type>",
    "payload": "<base64url of payload JSON>",
    "signatures": [
        { "keyid": "<key identifier>", "sig": "<base64url of signature>" }
    ]
}

PAE (Pre-Authentication Encoding) is signed per DSSE spec:
PAE = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(payload) + SP + payload
where LEN(s) is ASCII decimal byte length.
"""

import json
import hashlib
import base64
import time
import uuid
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional

from keyregistry import KeyRegistry


PAYLOAD_TYPE = "application/vnd.canonicalizer.receipt+json"


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (PAE).

    PAE(type, payload) = "DSSEv1" + " " + LEN(type) + " " + type
                         + " " + LEN(payload) + " " + payload

    Per spec, LEN(s) is the ASCII decimal representation of the byte
    length, with no leading zeros.
    Ref: https://github.com/secure-systems-lab/dsse/blob/master/envelope.md
    """
    t = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(t)).encode("utf-8") + b" " + t
        + b" "
        + str(len(payload)).encode("utf-8") + b" " + payload
    )


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding (per DSSE spec)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode, re-adding padding as needed."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# ── Data structures ───────────────────────────────────────────────────


@dataclass
class ReceiptPayload:
    """The attestation payload that gets signed inside the DSSE envelope."""

    receipt_id: str
    frozen_hash: str
    canonical_form_hash: str
    policy_version: str
    hash_algorithm: str
    timestamp_utc: str

    def to_bytes(self) -> bytes:
        return json.dumps(
            asdict(self), separators=(",", ":"), sort_keys=True
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "ReceiptPayload":
        d = json.loads(data)
        return cls(**d)


@dataclass
class DSSESignature:
    """A single signature entry in the DSSE envelope."""

    keyid: str
    sig: str  # base64url-encoded


@dataclass
class DSSEEnvelope:
    """DSSE envelope per https://github.com/secure-systems-lab/dsse."""

    payloadType: str
    payload: str  # base64url-encoded ReceiptPayload JSON
    signatures: list[DSSESignature] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "payloadType": self.payloadType,
            "payload": self.payload,
            "signatures": [
                {"keyid": s.keyid, "sig": s.sig} for s in self.signatures
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_json(cls, data: str) -> "DSSEEnvelope":
        d = json.loads(data)
        sigs = [DSSESignature(**s) for s in d.get("signatures", [])]
        return cls(
            payloadType=d["payloadType"],
            payload=d["payload"],
            signatures=sigs,
        )

    def get_payload(self) -> ReceiptPayload:
        """Decode and parse the payload."""
        raw = _b64url_decode(self.payload)
        return ReceiptPayload.from_bytes(raw)


# ── Signer ────────────────────────────────────────────────────────────


class ReceiptSigner:
    """Sign DSSE-envelope receipts using a key from a KeyRegistry.

    The signer resolves the active signing key from the registry by keyid.
    It never exposes private key material in the envelope.
    """

    def __init__(self, registry: KeyRegistry, keyid: Optional[str] = None):
        """
        Args:
            registry: KeyRegistry containing the signing key.
            keyid: Specific key to sign with. Defaults to registry's active key.
        """
        self._registry = registry
        self._keyid = keyid or registry.active_keyid
        if not self._keyid:
            raise ValueError(
                "No keyid specified and no active key in registry"
            )
        key = registry.get_valid(self._keyid)
        if not key:
            raise ValueError(
                f"Key '{self._keyid}' not found or not valid in registry"
            )

    @property
    def keyid(self) -> str:
        return self._keyid

    def sign(
        self,
        frozen_hash: str,
        canonical_form: str,
        policy_version: str,
        hash_algorithm: str = "SHA-256",
    ) -> DSSEEnvelope:
        """Create a DSSE-envelope signed receipt.

        The signing key is resolved from the registry by keyid.
        """
        cf_hash = hashlib.sha256(canonical_form.encode("utf-8")).hexdigest()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        receipt_id = str(uuid.uuid4())

        payload = ReceiptPayload(
            receipt_id=receipt_id,
            frozen_hash=frozen_hash,
            canonical_form_hash=cf_hash,
            policy_version=policy_version,
            hash_algorithm=hash_algorithm,
            timestamp_utc=timestamp,
        )
        payload_bytes = payload.to_bytes()
        payload_b64 = _b64url_encode(payload_bytes)

        # PAE: the thing we actually sign (prevents type confusion)
        pae_bytes = _pae(PAYLOAD_TYPE, payload_bytes)
        sig_bytes = self._registry.sign_bytes(self._keyid, pae_bytes)
        sig_b64 = _b64url_encode(sig_bytes)

        return DSSEEnvelope(
            payloadType=PAYLOAD_TYPE,
            payload=payload_b64,
            signatures=[DSSESignature(keyid=self._keyid, sig=sig_b64)],
        )


# ── Verifier ──────────────────────────────────────────────────────────


class ReceiptVerifier:
    """Verify DSSE-envelope receipts using a KeyRegistry.

    The verifier resolves public key material from the registry using
    the keyid embedded in the envelope. It does NOT need access to
    private key material (for ECDSA). For HMAC, the shared secret
    must be loaded into the registry via a secure channel.

    This class is intentionally separate from ReceiptSigner to enforce
    the trust boundary: signers and verifiers can operate independently
    as long as they share the same KeyRegistry (or a public export of it).
    """

    def __init__(self, registry: KeyRegistry):
        """
        Args:
            registry: KeyRegistry containing public verification material.
                      Can be loaded from a public export file.
        """
        self._registry = registry

    def verify(
        self,
        envelope: DSSEEnvelope,
        enforce_sign_time_validity: bool = True,
    ) -> "VerificationResult":
        """Verify a DSSE envelope.

        Checks (in order):
          1. payloadType matches expected type
          2. At least one signature present
          3. keyid resolves in registry
          4. Key is not revoked
          5. Key algorithm is consistent (not mismatched)
          6. PAE signature is cryptographically valid
          7. Key was valid at signing time (if enforce_sign_time_validity)

        Args:
            envelope: The DSSE envelope to verify.
            enforce_sign_time_validity: If True (default), verify that
                the signing key had not expired at the time the receipt
                was created (payload.timestamp_utc < key.expires_utc).
                Revoked keys are always rejected regardless.

        Returns a VerificationResult with details.
        """
        payload_bytes = _b64url_decode(envelope.payload)
        pae_bytes = _pae(envelope.payloadType, payload_bytes)

        # 1. Check payloadType
        if envelope.payloadType != PAYLOAD_TYPE:
            return VerificationResult(
                valid=False,
                keyid=None,
                reason=f"Unexpected payloadType: {envelope.payloadType}",
            )

        # 2. Check signatures present
        if not envelope.signatures:
            return VerificationResult(
                valid=False,
                keyid=None,
                reason="No signatures in envelope",
            )

        # Parse payload for sign-time check
        try:
            payload = ReceiptPayload.from_bytes(payload_bytes)
        except Exception as e:
            return VerificationResult(
                valid=False,
                keyid=None,
                reason=f"Malformed payload: {e}",
            )

        # Try each signature
        errors = []
        for sig_entry in envelope.signatures:
            keyid = sig_entry.keyid
            key = self._registry.get(keyid)

            # 3. Key exists
            if not key:
                errors.append(f"{keyid}: not found in registry")
                continue

            # 4. Key not revoked (always enforced)
            if key.revoked_utc is not None:
                errors.append(f"{keyid}: key revoked at {key.revoked_utc}")
                continue

            # 5. Algorithm consistency check
            # Map key algorithms to expected signature characteristics
            expected_algos = {
                "HMAC-SHA256": "HMAC-SHA256",
                "ECDSA-P256": "ECDSA-P256",
            }
            if key.algorithm not in expected_algos:
                errors.append(
                    f"{keyid}: unknown algorithm '{key.algorithm}'"
                )
                continue

            # 6. Cryptographic verification
            sig_bytes = _b64url_decode(sig_entry.sig)
            if not self._registry.verify_bytes(keyid, pae_bytes, sig_bytes):
                errors.append(f"{keyid}: signature mismatch")
                continue

            # 7. Sign-time validity check
            signed_while_valid = True
            sign_time_note = None
            if enforce_sign_time_validity and key.expires_utc:
                if payload.timestamp_utc >= key.expires_utc:
                    signed_while_valid = False
                    sign_time_note = (
                        f"key expired {key.expires_utc}, "
                        f"receipt signed {payload.timestamp_utc}"
                    )
                    errors.append(
                        f"{keyid}: signed after key expiry ({sign_time_note})"
                    )
                    continue

            return VerificationResult(
                valid=True,
                keyid=keyid,
                reason="Signature valid",
                key_algorithm=key.algorithm,
                key_created=key.created_utc,
                key_expires=key.expires_utc,
                signed_while_valid=signed_while_valid,
                sign_time_note=sign_time_note,
            )

        return VerificationResult(
            valid=False,
            keyid=None,
            reason="; ".join(errors),
        )


@dataclass
class VerificationResult:
    """Detailed result of envelope verification."""

    valid: bool
    keyid: Optional[str]
    reason: str
    key_algorithm: Optional[str] = None
    key_created: Optional[str] = None
    key_expires: Optional[str] = None
    signed_while_valid: Optional[bool] = None  # key was not expired at signing time
    sign_time_note: Optional[str] = None  # explanation if sign-time check is relevant

    def __bool__(self) -> bool:
        return self.valid


# ── Persistence ───────────────────────────────────────────────────────


def save_receipts(
    receipts: list[DSSEEnvelope], directory: str = "evidence/receipts"
) -> Path:
    """Save DSSE envelopes as individual JSON files with a manifest."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    manifest = []
    for envelope in receipts:
        payload = envelope.get_payload()
        filename = f"{payload.receipt_id}.dsse.json"
        filepath = out / filename
        filepath.write_text(envelope.to_json())
        manifest.append({
            "receipt_id": payload.receipt_id,
            "frozen_hash": payload.frozen_hash,
            "file": str(filepath),
        })
    manifest_path = out / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    return manifest_path
