# ADR 0004: Caller-asserted evidence stays labeled unverified

## Status

Accepted for v0.1.

## Context

The product story includes collectors and signed evidence bundles. Neither exists. A snapshot field named `confidence: confirmed` must not be rendered as if Verdict had confirmed it.

## Decision

- Snapshots must set `evidence_trust` to `caller_asserted`. Other values are errors.
- Reports set `evidence_trust` to `caller_asserted_unverified` on every verdict.
- The engine never increases confidence.
- `basis` is an enum: `observed`, `attested`, `inferred`. Only `observed` can appear in a strict `not_affected` proof. `inferred` is dropped. `attested` can support Kleene true/false, including `affected`, and cannot support `not_affected`.
- `manual_attestation` requires `expires_at`. Missing expiry or an expiry at or before the evaluation time makes the leaf unknown.
- Sample files are synthetic. Pack text and the README say so.

## Consequences

A reviewed synthetic test can reach `not_affected` because the fixture claims `basis: observed` and `confidence: high`. That tests the logic. It does not demonstrate an evidence pipeline.

A later collector has to record its own identity and the command it ran. Until those fields exist, bolting a "verified" enum onto the snapshot would be a false claim, so the loader refuses it.

## Alternatives

Ignoring `basis` and trusting every JSON value equally would let inferred "not listening" clear a finding. Hashing the snapshot and calling the hash a signature would be theater. Both were rejected.
