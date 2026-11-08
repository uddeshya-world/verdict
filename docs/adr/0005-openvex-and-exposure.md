# ADR 0005: Internal state is richer than OpenVEX; exposure is not exploitability's opposite

## Status

Accepted for v0.1.

## Context

The design notes use four operator-facing states and map them onto VEX. OpenVEX has `affected`, `not_affected`, `fixed`, and `under_investigation`. It has no "vulnerable but not exposed" status. The minimal VEX profile also requires `action_statement` when status is `affected`, and a `justification` or `impact_statement` when status is `not_affected`.

## Decision

Internal states:

| State | OpenVEX `status` | Extra fields |
| --- | --- | --- |
| `exploitable` | `affected` | `action_statement` from the pack remediation. `exposure_uncertainty` may be true |
| `vulnerable_not_exposed` | `affected` | Same. `status_notes` carry the internal state so a consumer can see it was not called exploitable |
| `not_affected` | `not_affected` | `justification` is the single label from the strict proof. No `impact_statement` |
| `needs_review` | `under_investigation` | `status_notes` list reasons and hints. No `justification` |

`fixed` is not emitted. A patched version is `not_affected` with `vulnerable_code_not_present` when the proof rules pass, or `needs_review` when they do not. Calling it `fixed` would skip the justification rule and would over-claim relative to a backport we did not verify.

Exposure classification, only if the condition tree is true:

- At least one fresh, high, observed record for the pack port and protocol, and every such record's zones are disjoint from `untrusted_zones` and do not contain `unknown`: `vulnerable_not_exposed`.
- Any such record intersecting `untrusted_zones`: `exploitable`, uncertainty false.
- No usable record, a low-confidence record, an inferred record, a stale record, or a zone of `unknown`: `exploitable` with `exposure_uncertainty: true` and reason `exposure_unknown_treated_as_exposed`.

Asset-level `zones` are not records. An asset labeled internal with no exposure observation is uncertain, not "not exposed".

Document `@id` values are `urn:verdict:...` URNs derived from the pack digest, knowledge-bundle version, evaluation time, and asset id. They are stable. They are not dereferenceable URLs. Vulnerability ids are `urn:cve:<id>` rather than an NVD URL, including for `CVE-2099-*` fixtures, so the document does not pretend NVD published the synthetic id.

`--author` is copied into the OpenVEX `author` field and is not authenticated. `role` states that the document is tool-assisted and that the evidence is unverified.

## Consequences

Two OpenVEX statements can both say `affected` while the JSON report distinguishes exploitable from internal-only. Consumers that only read `status` will treat internal-only as affected, which matches the design notes.

Documents are validated in tests against `schemas/openvex.schema.json`, copied from openvex/spec commit `a68ccd19b15a9604d28ef66ebf33f27a772ba4ec`. Validation of the schema's `format` annotations depends on the library version pinned in `go.mod`; the test fails if validation cannot be performed. Import into Dependency-Track has not been run and is not claimed.

## Alternatives

Using `not_affected` plus justification `vulnerable_code_cannot_be_controlled_by_adversary` for "not on the internet" was rejected. The design notes and the task statement both say isolation is still affected.
