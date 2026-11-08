# Contributing

Verdict is licensed under the Apache License, Version 2.0. Copyright is held by Uddeshya Kumar. By submitting a contribution you agree it is under those terms. See `LICENSE`.

## What "done" means here

v0.1 is a deterministic, offline condition-tree evaluator. Changes should keep these properties true:

- `not_affected` is emitted only for a reviewed pack with a sufficient observed proof. See `docs/adr/0002-not-affected-proof.md`.
- Draft packs, unknown leaves, incomplete inventory, stale or expired evidence, and unsupported version schemes do not become `not_affected`.
- Exposure never flips a result between `affected` and `not_affected`.
- The engine does not read the clock, the network, or the filesystem. Callers pass evaluation time and knowledge-bundle version in.
- Pack YAML cannot carry arbitrary code. New check kinds need an explicit evaluator and tests, and unknown kinds stay rejected.
- Real CVE ids in this repository stay `status: draft` with an empty `reviewers` list unless a genuine review happened and is recorded. Do not invent reviewer names. Synthetic fixtures use `CVE-2099-*`, `synthetic: true`, and the `synthetic-reviewer-*` names.

## Development

```bash
go test ./...
gofmt -l $(find . -name '*.go')
go test -fuzz=FuzzLoad -fuzztime=5s ./internal/pack
./scripts/demo.sh
```

Go 1.22.2 is the version CI uses. `go test ./...` is offline. It does not dial out. Fuzzing the loader should stay bounded; do not point the tool at production networks.

`UPDATE_GOLDEN=1 go test ./internal/cli` rewrites golden JSON. Review the diff. Goldens are canonical bytes, including key order.

## Pack contributions

1. Add a draft under `packs/draft/` or, for a fixture that must exercise `not_affected`, under `packs/synthetic/`.
2. Cite primary advisories you actually used. If a precondition is uncertain, leave the check out and say so in `limitations` rather than encoding a guess that can falsify the tree.
3. `verdict pack lint` must pass. `tests` entries point at local JSON snapshots. v0.1 does not build container fixtures.
4. Distro package types (`deb`, `rpm`, `apk`) are not "fixed" by sorting an upstream version. Supply an advisory fact in the fixture or expect `needs_review`.

Reviewed status requires two distinct human reviewers, a public review record, and fixture tests. The policy is in `docs/governance.md`. A YAML edit that only fills in `reviewers` is not a review.

## Review culture

Prefer small changes with tests. Do not add scheduled CI, phone-home telemetry, or a default that treats missing evidence as "not vulnerable".
