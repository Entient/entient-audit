"""
canonicalizer.py — Auditor-grade deterministic canonicalization engine.

Reads policy_spec.toml for all normalization rules.
Produces canonical forms (CF) and frozen hashes (FH).
Policy version is bound into the CF to prevent cross-version collisions.

Usage:
    from canonicalizer import Canonicalizer
    c = Canonicalizer("policy_spec.toml")
    cf = c.canonical_form(obj)
    fh = c.frozen_hash(obj)
"""

import json
import hashlib
import unicodedata
import re
from datetime import datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Optional

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # pip install tomli for 3.9/3.10
    except ImportError:
        raise ImportError(
            "Requires Python 3.11+ (tomllib) or `pip install tomli` for older versions."
        )


class Canonicalizer:
    """Policy-driven deterministic canonicalizer."""

    def __init__(self, policy_path: str = "policy_spec.toml"):
        self.policy_path = Path(policy_path)
        self.policy = self._load_policy()
        self.policy_version = self.policy["policy_version"]
        self.hash_algorithm = self.policy.get("hash", {}).get("algorithm", "SHA-256")
        self.hash_output = self.policy.get("hash", {}).get("output_encoding", "hex")

        # Build synonym lookup (variant -> canonical), lowercased for matching
        self._synonyms = {}
        syn_conf = self.policy.get("synonyms", {})
        self._synonyms_enabled = syn_conf.get("enabled", False)
        if self._synonyms_enabled:
            for variant, canonical in syn_conf.get("mappings", {}).items():
                self._synonyms[variant.lower()] = canonical

        # Nonce field exclusion set (lowercased)
        nonce_conf = self.policy.get("nonces", {})
        self._exclude_nonces = nonce_conf.get("exclude_from_canonical_form", False)
        self._nonce_fields = set(
            f.lower() for f in nonce_conf.get("excluded_fields", [])
        )

        # Timestamp config
        ts_conf = self.policy.get("timestamp_normalization", {})
        self._ts_mode = ts_conf.get("mode", "exact")  # exact | bucket | strip
        self._ts_granularity = ts_conf.get("bucket_granularity", "day")
        self._ts_tz = ts_conf.get("timezone_normalization", "UTC")
        self._ts_ignore_non_substantive = ts_conf.get(
            "ignore_if_marked_non_substantive", False
        )
        # Field names recognized as timestamps (lowercased for matching)
        self._ts_fields = set(
            f.lower() for f in ts_conf.get("timestamp_fields", [
                "timestamp", "created_at", "updated_at", "modified_at",
                "date", "datetime", "time", "ts",
            ])
        )
        # Fields explicitly marked non-substantive (always stripped)
        self._ts_non_substantive_fields = set(
            f.lower() for f in ts_conf.get("non_substantive_fields", [
                "timestamp",  # backward-compatible default
            ])
        )

        # Numeric config
        json_conf = self.policy.get("json_normalization", {})
        self._numeric_normalization = json_conf.get("numeric_normalization", True)
        self._remove_null = json_conf.get("remove_null_fields", True)
        self._remove_empty_strings = json_conf.get("remove_empty_strings", False)
        self._sort_keys = json_conf.get("sort_keys", True)

        # String config
        str_conf = self.policy.get("string_normalization", {})
        self._trim_whitespace = str_conf.get("trim_whitespace", True)
        self._collapse_whitespace = str_conf.get("collapse_internal_whitespace", True)
        self._lowercase = str_conf.get("lowercase_strings", False)

        # Encoding config
        enc_conf = self.policy.get("encoding", {})
        self._unicode_norm = enc_conf.get("unicode_normalization", "NFC")

        # List/set config
        list_conf = self.policy.get("list_normalization", {})
        self._sort_sets = list_conf.get("sort_sets", True)
        self._dedup_sets = list_conf.get("deduplicate_sets", False)

    def _load_policy(self) -> dict:
        if not self.policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {self.policy_path}")
        with open(self.policy_path, "rb") as f:
            return tomllib.load(f)

    # ── String normalization ──────────────────────────────────────────

    def _normalize_string(self, s: str) -> str:
        """Apply full string normalization pipeline."""
        # Unicode normalization
        s = unicodedata.normalize(self._unicode_norm, s)
        # Whitespace
        if self._trim_whitespace:
            s = s.strip()
        if self._collapse_whitespace:
            s = re.sub(r"\s+", " ", s)
        # Case
        if self._lowercase:
            s = s.lower()
        # Synonym substitution (word-boundary aware)
        if self._synonyms_enabled:
            s = self._apply_synonyms(s)
        return s

    def _apply_synonyms(self, s: str) -> str:
        """Replace known synonyms with canonical forms.

        Uses longest-match-first to handle overlapping synonyms
        (e.g., 'U.S.A.' before 'U.S.').

        Word-boundary safe: "US" won't match inside "mUSEum" or "RUST".
        Dotted abbreviations (e.g., "U.S.") use lookahead/lookbehind
        to avoid matching inside longer tokens.
        """
        if not self._synonyms:
            return s
        # Sort by length descending so longer matches take priority
        sorted_variants = sorted(self._synonyms.keys(), key=len, reverse=True)
        for variant in sorted_variants:
            canonical = self._synonyms[variant]
            escaped = re.escape(variant)
            # Dotted abbreviations: use lookaround for non-alnum boundaries
            # (standard \b doesn't work well with trailing dots)
            if "." in variant:
                pattern = re.compile(
                    r"(?<![A-Za-z0-9.])" + escaped + r"(?![A-Za-z0-9])",
                    re.IGNORECASE,
                )
            else:
                # Standard word boundary for plain tokens
                pattern = re.compile(
                    r"\b" + escaped + r"\b",
                    re.IGNORECASE,
                )
            s = pattern.sub(canonical, s)
        return s

    # ── Numeric normalization ─────────────────────────────────────────

    def _normalize_number(self, n: Any) -> str:
        """Normalize numeric values to shortest non-scientific decimal string."""
        try:
            d = Decimal(str(n))
            # Handle negative zero
            if d == 0:
                d = Decimal("0")
            # Normalize removes trailing zeros: 1.000 -> 1
            d = d.normalize()
            # Prevent scientific notation: 1E+2 -> 100
            # Use to_eng_string and then fix if needed
            s = str(d)
            if "E" in s or "e" in s:
                # Force plain decimal representation
                s = format(d, "f")
                # Strip trailing zeros after decimal point
                if "." in s:
                    s = s.rstrip("0").rstrip(".")
            return s
        except (InvalidOperation, ValueError):
            return str(n)

    # ── Timestamp normalization ──────────────────────────────────────

    def _parse_iso_timestamp(self, s: str) -> Optional[datetime]:
        """Try to parse a string as an ISO 8601 timestamp."""
        # Common ISO formats: 2025-01-01T00:00:00Z, 2025-01-01T00:00:00+05:00
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(s, fmt)
                return dt
            except ValueError:
                continue
        return None

    def _bucket_timestamp(self, dt: datetime) -> str:
        """Normalize a datetime to UTC and bucket by configured granularity.

        Returns a deterministic ISO string truncated to the bucket boundary.
        """
        # Normalize to UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)

        # Bucket
        g = self._ts_granularity
        if g == "day":
            bucketed = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        elif g == "hour":
            bucketed = dt.replace(minute=0, second=0, microsecond=0)
        elif g == "minute":
            bucketed = dt.replace(second=0, microsecond=0)
        elif g == "second":
            bucketed = dt.replace(microsecond=0)
        else:
            bucketed = dt  # "exact" or unknown → pass through

        return bucketed.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _normalize_timestamp_value(self, key: str, value: str) -> Optional[str]:
        """Apply timestamp policy to a string value in a timestamp field.

        Returns:
            - None if the field should be stripped (non-substantive)
            - Bucketed ISO string if mode=bucket and parseable
            - Original string if not parseable as timestamp
        """
        norm_key = key.lower()

        # Strip non-substantive timestamp fields entirely
        if (
            self._ts_ignore_non_substantive
            and norm_key in self._ts_non_substantive_fields
        ):
            return None  # signals caller to skip this field

        # Only bucket recognized timestamp fields
        if norm_key not in self._ts_fields:
            return value  # not a timestamp field, pass through

        if self._ts_mode == "strip":
            return None
        elif self._ts_mode == "bucket":
            dt = self._parse_iso_timestamp(value)
            if dt is not None:
                return self._bucket_timestamp(dt)
            return value  # unparseable → pass through unchanged
        else:
            # "exact" mode → pass through
            return value

    # ── Core canonicalization ─────────────────────────────────────────

    def canonicalize(
        self, obj: Any, set_fields: Optional[set] = None
    ) -> Any:
        """Recursively canonicalize an object according to policy."""
        if set_fields is None:
            set_fields = set()

        if isinstance(obj, str):
            return self._normalize_string(obj)

        elif isinstance(obj, bool):
            # Must check bool before int (bool is subclass of int in Python)
            return obj

        elif isinstance(obj, (int, float)):
            if self._numeric_normalization:
                return self._normalize_number(obj)
            return obj

        elif isinstance(obj, list):
            return [self.canonicalize(x, set_fields) for x in obj]

        elif isinstance(obj, dict):
            cleaned = {}
            keys = sorted(obj.keys()) if self._sort_keys else list(obj.keys())
            for k in keys:
                v = obj[k]
                norm_key = self._normalize_string(k)

                # Nonce exclusion
                if self._exclude_nonces and norm_key.lower() in self._nonce_fields:
                    continue

                # Null exclusion
                if v is None and self._remove_null:
                    continue

                # Empty string exclusion (if policy says so)
                if isinstance(v, str) and v == "" and self._remove_empty_strings:
                    continue

                # Timestamp normalization (bucket, strip, or pass through)
                if isinstance(v, str):
                    ts_result = self._normalize_timestamp_value(norm_key, v)
                    if ts_result is None:
                        continue  # field stripped by policy
                    v = ts_result

                # Recurse
                canon_v = self.canonicalize(v, set_fields)

                # Handle set-typed list fields (sort elements)
                if (
                    norm_key in set_fields
                    and isinstance(canon_v, list)
                    and self._sort_sets
                ):
                    canon_v = sorted(
                        canon_v, key=lambda x: json.dumps(x, sort_keys=True)
                    )
                    if self._dedup_sets:
                        seen = []
                        for item in canon_v:
                            if item not in seen:
                                seen.append(item)
                        canon_v = seen

                cleaned[norm_key] = canon_v
            return cleaned
        else:
            return obj

    def canonical_form(
        self,
        obj: Any,
        set_fields: Optional[set] = None,
        bind_policy_version: bool = True,
    ) -> str:
        """Produce the deterministic canonical form string.

        If bind_policy_version is True (default), the policy version is
        included as an envelope around the canonical data. This prevents
        CFs generated under different policy versions from colliding.
        """
        normalized = self.canonicalize(obj, set_fields)

        if bind_policy_version:
            envelope = {
                "_policy_version": self.policy_version,
                "data": normalized,
            }
            return json.dumps(envelope, separators=(",", ":"), sort_keys=True)
        else:
            return json.dumps(normalized, separators=(",", ":"), sort_keys=True)

    def frozen_hash(
        self,
        obj: Any,
        set_fields: Optional[set] = None,
        bind_policy_version: bool = True,
    ) -> str:
        """Produce the frozen hash of the canonical form."""
        cf = self.canonical_form(obj, set_fields, bind_policy_version)
        algo = self.hash_algorithm.replace("-", "").lower()  # SHA-256 -> sha256
        h = hashlib.new(algo, cf.encode("utf-8"))
        if self.hash_output == "base64":
            import base64
            return base64.b64encode(h.digest()).decode("ascii")
        return h.hexdigest()

    def input_hash(self, obj: Any) -> str:
        """Hash the raw input (pre-canonicalization) for traceability."""
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True)
        algo = self.hash_algorithm.replace("-", "").lower()
        return hashlib.new(algo, raw.encode("utf-8")).hexdigest()


# ── Convenience functions (backward-compatible with stub API) ─────────

_default_canonicalizer: Optional[Canonicalizer] = None


def _get_default() -> Canonicalizer:
    global _default_canonicalizer
    if _default_canonicalizer is None:
        _default_canonicalizer = Canonicalizer()
    return _default_canonicalizer


def canonical_form(obj: Any) -> str:
    return _get_default().canonical_form(obj)


def frozen_hash(obj: Any) -> str:
    return _get_default().frozen_hash(obj)
