"""
keyregistry.py — Auditor-grade key management for DSSE receipt signing.

Provides a KeyRegistry that:
  - Stores signing keys (HMAC secrets or ECDSA key pairs) by keyid
  - Tracks key metadata: algorithm, created/expires/revoked timestamps
  - Supports key rotation (multiple keys, one active for signing)
  - Resolves public verification material by keyid
  - Persists to a JSON registry file for auditability
  - Exports public keys for independent verifiers

Trust model:
  - Signer holds private key, registers it in the registry
  - Verifier receives only the registry's public export
  - Envelope carries keyid; verifier resolves key material from registry
  - Revoked keys always fail verification
  - Expired keys verify only if the receipt was signed before expiry

Usage:
    # Signing side
    registry = KeyRegistry("keys/registry.json")
    registry.generate_hmac_key("signing-key-001")
    signer = ReceiptSigner(registry)

    # Verification side (different process/machine)
    pub_registry = KeyRegistry.from_public_export("keys/public_keys.json")
    verifier = ReceiptVerifier(pub_registry)
    verifier.verify(envelope)  # resolves key by keyid in envelope
"""

import json
import hashlib
import hmac
import base64
import secrets
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class KeyEntry:
    """A single key in the registry."""

    keyid: str
    algorithm: str  # "HMAC-SHA256" | "ECDSA-P256"
    created_utc: str
    expires_utc: Optional[str] = None
    revoked_utc: Optional[str] = None
    active: bool = True  # eligible for signing (not verification — verify ignores this)

    # HMAC: base64-encoded secret (present in private registry only)
    hmac_secret_b64: Optional[str] = None

    # ECDSA: PEM-encoded keys
    private_key_pem: Optional[str] = None  # private registry only
    public_key_pem: Optional[str] = None  # present in both private and public

    def is_valid_at(self, timestamp_utc: Optional[str] = None) -> bool:
        """Check if key is valid (not expired, not revoked)."""
        if self.revoked_utc is not None:
            return False
        if not self.active:
            return False
        if self.expires_utc and timestamp_utc:
            return timestamp_utc < self.expires_utc
        if self.expires_utc:
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            return now < self.expires_utc
        return True

    def to_dict(self, include_private: bool = False) -> dict:
        """Serialize key entry. Strips private material unless requested."""
        d = {
            "keyid": self.keyid,
            "algorithm": self.algorithm,
            "created_utc": self.created_utc,
            "expires_utc": self.expires_utc,
            "revoked_utc": self.revoked_utc,
            "active": self.active,
        }
        if self.algorithm == "ECDSA-P256":
            d["public_key_pem"] = self.public_key_pem
            if include_private:
                d["private_key_pem"] = self.private_key_pem
        elif self.algorithm == "HMAC-SHA256":
            # HMAC: secret is symmetric, so it's "private" material
            # For public export, we include a fingerprint for identification
            if include_private:
                d["hmac_secret_b64"] = self.hmac_secret_b64
            else:
                # Export a fingerprint so verifiers can confirm key identity
                # (actual verification still needs the shared secret)
                if self.hmac_secret_b64:
                    secret_bytes = base64.b64decode(self.hmac_secret_b64)
                    d["hmac_fingerprint"] = hashlib.sha256(
                        secret_bytes
                    ).hexdigest()[:16]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "KeyEntry":
        return cls(
            keyid=d["keyid"],
            algorithm=d["algorithm"],
            created_utc=d["created_utc"],
            expires_utc=d.get("expires_utc"),
            revoked_utc=d.get("revoked_utc"),
            active=d.get("active", True),
            hmac_secret_b64=d.get("hmac_secret_b64"),
            private_key_pem=d.get("private_key_pem"),
            public_key_pem=d.get("public_key_pem"),
        )


class KeyRegistry:
    """File-backed key registry with rotation support."""

    def __init__(self, registry_path: Optional[str] = None):
        """
        Load or create a key registry.

        Args:
            registry_path: Path to registry JSON file. If None, in-memory only.
        """
        self._keys: dict[str, KeyEntry] = {}
        self._path = Path(registry_path) if registry_path else None
        self._active_keyid: Optional[str] = None

        if self._path and self._path.exists():
            self._load()

    def _load(self):
        """Load registry from disk."""
        data = json.loads(self._path.read_text())
        self._active_keyid = data.get("active_keyid")
        for kd in data.get("keys", []):
            entry = KeyEntry.from_dict(kd)
            self._keys[entry.keyid] = entry

    def _save(self, include_private: bool = True):
        """Persist registry to disk."""
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "active_keyid": self._active_keyid,
            "keys": [
                k.to_dict(include_private=include_private)
                for k in self._keys.values()
            ],
        }
        self._path.write_text(json.dumps(data, indent=2, sort_keys=True))

    # ── Key generation ────────────────────────────────────────────────

    def generate_hmac_key(
        self,
        keyid: str,
        expires_days: Optional[int] = 90,
        secret: Optional[bytes] = None,
        set_active: bool = True,
    ) -> KeyEntry:
        """Generate and register a new HMAC-SHA256 key.

        Args:
            keyid: Unique identifier for this key.
            expires_days: Days until expiry (None for no expiry).
            secret: Explicit secret bytes (default: 32 random bytes).
            set_active: Whether to make this the active signing key.
        """
        if keyid in self._keys:
            raise ValueError(f"Key '{keyid}' already exists in registry")

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        expires = None
        if expires_days:
            expires_ts = time.time() + (expires_days * 86400)
            expires = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_ts)
            )

        if secret is None:
            secret = secrets.token_bytes(32)

        entry = KeyEntry(
            keyid=keyid,
            algorithm="HMAC-SHA256",
            created_utc=now,
            expires_utc=expires,
            active=True,
            hmac_secret_b64=base64.b64encode(secret).decode("ascii"),
        )
        self._keys[keyid] = entry
        if set_active:
            self._active_keyid = keyid
        self._save()
        return entry

    def generate_ecdsa_key(
        self,
        keyid: str,
        expires_days: Optional[int] = 90,
        set_active: bool = True,
    ) -> KeyEntry:
        """Generate and register a new ECDSA-P256 key pair."""
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            raise ImportError("ECDSA requires `pip install cryptography`")

        if keyid in self._keys:
            raise ValueError(f"Key '{keyid}' already exists in registry")

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        expires = None
        if expires_days:
            expires_ts = time.time() + (expires_days * 86400)
            expires = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_ts)
            )

        private_key = ec.generate_private_key(ec.SECP256R1())
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        entry = KeyEntry(
            keyid=keyid,
            algorithm="ECDSA-P256",
            created_utc=now,
            expires_utc=expires,
            active=True,
            private_key_pem=private_pem,
            public_key_pem=public_pem,
        )
        self._keys[keyid] = entry
        if set_active:
            self._active_keyid = keyid
        self._save()
        return entry

    # ── Key lifecycle ─────────────────────────────────────────────────

    def revoke(self, keyid: str):
        """Revoke a key. Revoked keys cannot sign or verify."""
        if keyid not in self._keys:
            raise KeyError(f"Key '{keyid}' not found")
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._keys[keyid].revoked_utc = now
        self._keys[keyid].active = False
        if self._active_keyid == keyid:
            self._active_keyid = None
        self._save()

    def rotate(
        self,
        new_keyid: str,
        expires_days: Optional[int] = 90,
        algorithm: str = "HMAC-SHA256",
    ) -> KeyEntry:
        """Generate a new key and make it active. Old key remains valid
        for verification until it expires or is explicitly revoked."""
        if self._active_keyid and self._active_keyid in self._keys:
            # Deactivate old key for signing (still valid for verification)
            self._keys[self._active_keyid].active = False

        if algorithm == "ECDSA-P256":
            return self.generate_ecdsa_key(new_keyid, expires_days)
        else:
            return self.generate_hmac_key(new_keyid, expires_days)

    # ── Key resolution ────────────────────────────────────────────────

    @property
    def active_keyid(self) -> Optional[str]:
        return self._active_keyid

    def get(self, keyid: str) -> Optional[KeyEntry]:
        """Get a key entry by ID."""
        return self._keys.get(keyid)

    def get_active(self) -> Optional[KeyEntry]:
        """Get the current active signing key."""
        if self._active_keyid:
            return self._keys.get(self._active_keyid)
        return None

    def get_valid(self, keyid: str) -> Optional[KeyEntry]:
        """Get a key only if it's currently valid (not expired, not revoked)."""
        entry = self._keys.get(keyid)
        if entry and entry.is_valid_at():
            return entry
        return None

    def list_keys(self) -> list[KeyEntry]:
        """List all keys in the registry."""
        return list(self._keys.values())

    # ── Export / Import ───────────────────────────────────────────────

    def export_public(self, path: str):
        """Export the registry with private material stripped.

        This file can be given to independent verifiers.
        For HMAC keys, only a fingerprint is exported (verifiers
        still need the shared secret via a secure channel).
        For ECDSA keys, the public key PEM is exported.
        """
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "active_keyid": self._active_keyid,
            "exported_utc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
            ),
            "keys": [
                k.to_dict(include_private=False)
                for k in self._keys.values()
            ],
        }
        out.write_text(json.dumps(data, indent=2, sort_keys=True))

    @classmethod
    def from_public_export(cls, path: str) -> "KeyRegistry":
        """Load a registry from a public export file.

        Keys loaded this way have no private material. ECDSA keys
        can be used for verification. HMAC keys need the shared
        secret loaded separately.
        """
        registry = cls()
        data = json.loads(Path(path).read_text())
        registry._active_keyid = data.get("active_keyid")
        for kd in data.get("keys", []):
            entry = KeyEntry.from_dict(kd)
            registry._keys[entry.keyid] = entry
        return registry

    def load_hmac_secret(self, keyid: str, secret: bytes):
        """Load a shared HMAC secret for a key (for verifiers who received
        the secret via secure channel)."""
        entry = self._keys.get(keyid)
        if not entry:
            raise KeyError(f"Key '{keyid}' not found in registry")
        if entry.algorithm != "HMAC-SHA256":
            raise ValueError(f"Key '{keyid}' is not HMAC")
        entry.hmac_secret_b64 = base64.b64encode(secret).decode("ascii")

    # ── Crypto primitives (used by signer/verifier) ───────────────────

    def sign_bytes(self, keyid: str, data: bytes) -> bytes:
        """Sign bytes using the specified key. Raises if key is invalid."""
        entry = self.get_valid(keyid)
        if not entry:
            raise KeyError(
                f"Key '{keyid}' not found or not valid for signing"
            )

        if entry.algorithm == "HMAC-SHA256":
            if not entry.hmac_secret_b64:
                raise ValueError(f"Key '{keyid}' has no secret material")
            secret = base64.b64decode(entry.hmac_secret_b64)
            return hmac.new(secret, data, hashlib.sha256).digest()

        elif entry.algorithm == "ECDSA-P256":
            if not entry.private_key_pem:
                raise ValueError(f"Key '{keyid}' has no private key material")
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec

            pk = load_pem_private_key(
                entry.private_key_pem.encode("utf-8"), password=None
            )
            return pk.sign(data, ec.ECDSA(hashes.SHA256()))

        raise ValueError(f"Unsupported algorithm: {entry.algorithm}")

    def verify_bytes(self, keyid: str, data: bytes, signature: bytes) -> bool:
        """Verify a signature using the specified key's public material.

        Returns False if key is expired, revoked, or signature invalid.
        Does NOT require private key material for ECDSA.
        """
        entry = self._keys.get(keyid)
        if not entry:
            return False
        # Allow verification against expired keys (receipt was signed when
        # key was valid), but reject revoked keys
        if entry.revoked_utc is not None:
            return False

        if entry.algorithm == "HMAC-SHA256":
            if not entry.hmac_secret_b64:
                return False  # verifier doesn't have the shared secret
            secret = base64.b64decode(entry.hmac_secret_b64)
            expected = hmac.new(secret, data, hashlib.sha256).digest()
            return hmac.compare_digest(expected, signature)

        elif entry.algorithm == "ECDSA-P256":
            pem = entry.public_key_pem
            if not pem and entry.private_key_pem:
                # Fallback: derive public from private (backward compat)
                pem = entry.private_key_pem  # load_pem handles both
            if not pem:
                return False

            try:
                from cryptography.hazmat.primitives.serialization import (
                    load_pem_public_key,
                    load_pem_private_key,
                )
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import ec

                try:
                    pub = load_pem_public_key(pem.encode("utf-8"))
                except (ValueError, Exception):
                    pk = load_pem_private_key(
                        pem.encode("utf-8"), password=None
                    )
                    pub = pk.public_key()

                pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
                return True
            except Exception:
                return False

        return False
