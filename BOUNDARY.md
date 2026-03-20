# Boundary: Core vs Audit

## One sentence

**Core issues receipts. Audit verifies them.**

## What the core does (entient, entient-agent, entient-interceptor)

- Issues Ed25519-signed receipts over canonical JSON
- Runs evaluators that assess closure integrity and I/O integrity
- Manages agent identity, delegation, trust tiers
- Enforces policy (allowed/denied/conditional)
- Issues workflow certificates with evaluator-backed state
- Uses content-addressed coordinates: `seal:<32hex>`, `obligation:<32hex>`
- Domain separation: `ENTIENT:<domain>:<version>`

## What this toolkit does (entient-audit)

- Verifies receipt signatures independently, offline, with only a public key
- Canonicalizes data deterministically for frozen-hash sameness proofs
- Signs DSSE envelopes over canonicalized content
- Manages key lifecycle (generation, rotation, revocation, public export)
- Recognizes evaluator claims as signed payload fields (does not re-evaluate them)

## What this toolkit does NOT do

- Run evaluators or assess trust chain correctness
- Issue receipts on behalf of the core
- Enforce policy decisions
- Manage agent identity or delegations
- Determine whether a closure state claim is accurate
- Execute any trust chain logic

## Why this boundary matters

An auditor needs to answer: "Is this receipt authentic?"
That question is purely cryptographic. It does not require running the evaluation pipeline.

The core answers: "What should the trust state be?"
That question requires evaluator logic, policy rules, and system context.

Mixing these concerns makes both harder to trust. Keeping them separate means:
- The audit toolkit stays small, rigorous, and independently trustworthy
- The core can evolve its evaluation logic without breaking verification
- Third parties can verify receipts without access to ENTIENT infrastructure

## Evaluator claims

Core receipts may contain evaluator-backed fields like:
- `closure_integrity_state` (clean / degraded / blocked)
- `closure_integrity_score` (0.0 - 1.0)
- `io_integrity_state` (verified / partial / unverified)
- `evaluator_coord`, `evaluator_role`

This toolkit surfaces these as informational context alongside the verification result. The signature proves the issuer attested to these values. Whether the evaluation was correct is outside audit scope.

## Coordinate formats

| Format | Example | Used by |
|--------|---------|---------|
| `seal:<32hex>` | `seal:a1b2c3d4e5f6...` | Core receipts |
| `obligation:<32hex>` | `obligation:9f8e7d6c...` | Core obligations |
| `sha256:<64hex>` | `sha256:abcdef0123...` | Audit DSSE envelopes |
| Bare hex | `a1b2c3d4e5f6...` | Legacy receipts |

All are content-addressed hashes over canonical content. This toolkit recognizes and validates all formats.
