# ENTIENT Audit Toolkit

Independent receipt verification and auditor-grade canonicalization.

**Core issues receipts. This toolkit verifies them.**

See [BOUNDARY.md](BOUNDARY.md) for the exact line between core and audit.

## Quick Start

Requires Python 3.9+.

```bash
pip install pynacl tomli   # tomli only needed for Python <3.11
make prove
```

## Independent Third-Party Verification

The primary use case: verify an ENTIENT receipt without trusting ENTIENT infrastructure.

```bash
# You received a receipt file from an agent workflow.
# You have the signer's public key (from published key registry).
# You trust nothing else.

python verify_canon_v1.py receipt.json --public-key <hex>
```

Output:
```
ENTIENT Independent Receipt Verification
============================================
  Format:  Core Trust Chain
  Receipt: seal:a1b2c3d4e5f6...
  Type:    certificate
  Signed:  2026-03-20T22:30:00Z
  Key:     a1b2c3d4e5f6...
  Coord:   seal:a1b2c3d4...

  PASS  signature
  PASS  payload_hash_format
  PASS  coordinate_format
  PASS  signer_key

  Evaluator claims (signed, not re-evaluated):
    closure_integrity_state: clean
    closure_integrity_score: 0.94

  VERDICT: Receipt is independently verified.
           No trust in ENTIENT infrastructure required.
           The signer attested to these contents.
```

Three receipt formats are supported:
- **Core trust chain** (`seal:` coordinates, Ed25519, domain separation)
- **ReceiptEnvelopeV1** (spatial DSSE envelopes)
- **Legacy** (canon_version 1, field exclusion)

The verifier auto-detects the format.

### What "verified" means

The signature is authentic and the content is untampered. The signer attested to these exact fields at the stated time.

### What "verified" does NOT mean

The evaluator's judgment was correct. If a receipt claims `closure_integrity_state: clean`, this tool confirms the claim was signed -- not that it was right. Evaluator correctness is the core's domain, not audit's.

## Canonicalization

Turns the question "are these two records the same?" into a single hash lookup.

Two inputs that differ only by noise (whitespace, key order, formatting, nonces, synonyms defined by policy, timestamps within the same bucket) produce **identical frozen hashes**. An auditor queries by hash and retrieves all equivalent records. Done.

## Files

| File | Purpose |
|------|---------|
| `verify_canon_v1.py` | **Standalone receipt verifier** -- the auditor's primary tool |
| `canonicalizer.py` | Deterministic canonical form + frozen hash engine |
| `keyregistry.py` | Key management: generation, rotation, revocation, public export |
| `receipts.py` | DSSE signing (ReceiptSigner) + independent verification (ReceiptVerifier) |
| `prove.py` | Single-command conformance proof runner with evidence output |
| `policy_spec.toml` | What counts as noise vs substance (versioned, `implemented` flags) |
| `conformance.jsonl` | 31 test vectors proving the canonicalizer works |
| `BOUNDARY.md` | Exact boundary between core (issues) and audit (verifies) |
| `Makefile` | Convenience targets |

## Trust Model

```
┌─────────────┐     signs with      ┌──────────────┐
│ KeyRegistry  │────keyid──────────▶ │ ReceiptSigner│──▶ DSSE Envelope
│ (private)    │                     └──────────────┘      │
└──────┬───────┘                                           │
       │ export_public()                                   │
       ▼                                                   ▼
┌──────────────┐    resolves key    ┌────────────────┐
│ KeyRegistry  │────by keyid──────▶ │ReceiptVerifier │◀── DSSE Envelope
│ (public)     │                    └────────────────┘
└──────────────┘
```

The signer and verifier are **separate classes** backed by **separate registry instances**. The verifier resolves key material from the envelope's `keyid` field using a public-only export of the registry.

### ECDSA-P256 (recommended for third-party / auditor verification)

The public export contains the full public key PEM. An independent verifier can verify any receipt using only `public_keys.json` — no secrets, no secure channel, no contact with the signer. This is the mode to use when an external auditor or counterparty needs to independently confirm receipt authenticity.

### HMAC-SHA256 (internal / shared-secret mode)

HMAC is symmetric: the same secret signs and verifies. The public export contains only a key fingerprint (truncated SHA-256 of the secret), which is sufficient to *identify* but not *verify* a key. The verifier needs the shared secret delivered through a secure channel (KMS, Vault, out-of-band exchange). Use this mode for internal systems where signer and verifier share infrastructure.

**Bottom line**: If your verifier is a different team, organization, or process boundary, use ECDSA. If signer and verifier share a secret store, HMAC is simpler and sufficient.

### Verification checks (in order)

1. `payloadType` matches expected media type
2. At least one signature present in envelope
3. `keyid` resolves in the verifier's registry
4. Key is not revoked (always enforced, immediate hard fail)
5. Key algorithm is known and consistent
6. PAE signature is cryptographically valid
7. Key was valid at signing time (`payload.timestamp_utc < key.expires_utc`)

Step 7 ensures that even if a key has since expired, receipts signed *while it was valid* still verify. Receipts signed *after* key expiry are rejected. Revoked keys are rejected unconditionally at step 4.

## Evidence Output

After `make prove`, the `evidence/` directory contains:

- `results.json` — vector-by-vector pass/fail with hashes
- `receipts/*.dsse.json` — DSSE envelopes with PAE-signed attestations
- `keys/registry.json` — full key registry (**private — do not share**)
- `keys/public_keys.json` — public export (**give to verifiers**)
- `summary.txt` — auditor-readable summary

## What's Enforced

- **String normalization**: Unicode NFC, whitespace collapse, word-boundary-safe synonym replacement
- **JSON normalization**: sorted keys, null removal, numeric shortest-form
- **Timestamp bucketing**: ISO parse → UTC normalize → bucket by day/hour/minute/second
- **Nonce exclusion**: configurable field names auto-stripped from CF
- **Policy version binding**: every CF includes `_policy_version` in its envelope
- **DSSE signing**: spec-correct PAE (ASCII decimal lengths), HMAC-SHA256 or ECDSA-P256
- **Key management**: registry-backed keyid resolution, rotation, revocation, public export

## What's Declared But Not Enforced

- **Binary normalization** (EXIF stripping, line endings): declared in policy for completeness, but must be handled by your ingestion layer before objects enter the canonicalizer

## Production Checklist

- [x] Add CI job to run `make prove` on every commit (Python 3.9/3.11/3.12 matrix)
- [x] Support core trust chain coordinate formats (`seal:`, `obligation:`)
- [x] Document boundary between core and audit ([BOUNDARY.md](BOUNDARY.md))
- [x] Surface evaluator claims as informational context (not execution)
- [ ] Switch to ECDSA-P256 for third-party verifiable receipts (`registry.generate_ecdsa_key(...)`)
- [ ] Store private registry in KMS/Vault, not on disk
- [ ] Distribute `public_keys.json` to verifiers (ECDSA: sufficient alone; HMAC: also share secret via secure channel)
- [ ] Add domain-specific vectors to `conformance.jsonl`
- [ ] Customize `policy_spec.toml` synonyms for your domain
- [ ] Implement binary preprocessing per `binary_normalization` policy
- [ ] Implement key rotation schedule per `signing.key_rotation_policy`
