# ADR 0002: `not_affected` requires a sufficient proof, not a false leaf

## Status

Accepted for v0.1. This ADR overrides shorthand in the design notes that says "the falsifying leaf" as if a tree had only one.

## Context

Kleene logic can make a tree false because one conjunct is false, or because every disjunct is false, or because a negated child is true. A walker that returns `not_affected` on the first false leaf mis-handles `any_of`, nested `not`, and mixed confidence.

False `not_affected` is the failure this project is built to avoid. False `exploitable` is the cheaper failure.

## Decision

1. Compute the Kleene value with `all_of`, `any_of`, and `not` exactly: unknown is absorbing when no stronger short-circuit applies (`all_of` short-circuits on false, `any_of` short-circuits on true).
2. Separately build a **strict false proof**:
   - A leaf is strict only when its value is the one the polarity requires, `basis` is observed, the observation is fresh, confidence is at least `high`, and `negation_justification` is set. The engine encodes polarity by constructing the leaf value before proof selection: a positive check contributes when it is false; a check under `not` contributes when it is true. The logic package then flips proofs through `not`.
   - `all_of` is strictly false when any child is strictly false. The selected child is the strict child with the highest confidence, tie-breaking to the earliest child.
   - `any_of` is strictly false only when every child is strictly false. Confidence is the minimum. Check ids are the union. This is the "entire sufficient proof" for a disjunction.
   - `not` turns a strict true proof into a strict false proof and the reverse. A strict true proof is the dual: every conjunct, a single chosen disjunct, observed, confidence at least `high`, justification present so a later `not` has a label.
3. Emit `not_affected` only when a strict false proof exists, its justifications collapse to exactly one OpenVEX label, the pack status is `reviewed`, at least two distinct reviewer names are present, the pack is not deprecated, and the confidence after `confidence_ceiling` is still at least `high`.
4. Otherwise a false or unknown tree is `needs_review` with resolution hints. The OpenVEX status is `under_investigation`. The machine-readable `justification` field is omitted so a consumer does not treat the note as a VEX justification.
5. A true tree is `exploitable` or `vulnerable_not_exposed` as in ADR 0005, including when the pack is draft. Draft status blocks `not_affected`. It does not block `affected`.
6. Low-confidence or attested falsifying leaves keep the Kleene value (so they do not flip the asset to `exploitable`) and are not strict (so they do not flip it to `not_affected`). Inferred and stale observations are downgraded to unknown before the tree runs, so they neither falsify nor satisfy.

## Consequences

Some assets that a human would call "probably not affected" stay `needs_review`. That is intentional.

Mixed justifications are `needs_review` even when the tree is strictly false. OpenVEX allows one justification per statement. Guessing one would publish a reason the proof does not uniformly support. A free-text `impact_statement` was rejected for the same reason: it would look like `not_affected` without a single machine-readable label the proof supports.

## Alternatives

- "Any false leaf" — rejected. It marks `any_of(false, unknown)` as not affected.
- Require every leaf in the whole tree to be high confidence before any `not_affected` — rejected. An unknown sibling of a strict false conjunct does not weaken that conjunct (`all_of` is already false).
- Allow draft packs to emit `not_affected` at low confidence — rejected by the design notes and by the task statement.
