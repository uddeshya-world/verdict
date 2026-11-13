# AGENTS.md

Instructions for coding agents (Codex, Cursor, Claude Code, and others). Two audiences: agents changing this repository, and agents using the `verdict` binary to answer questions about CVEs. The machine contract (exit codes, JSON shapes, stability) is [docs/agents.md](docs/agents.md).

## The invariant

**Verdict never emits a false `not_affected`.** `not_affected` comes only from observed, fresh, high-confidence evidence that falsifies a precondition of a pack reviewed by two humans. Unknown, stale, inferred, attested, low-confidence, or draft-pack evidence is never enough. See [docs/adr/0002-not-affected-proof.md](docs/adr/0002-not-affected-proof.md). When in doubt, the answer is `needs_review` or `exploitable`, never `not_affected`.

## Working on this repository

Build and test (Go toolchain from `go.mod`):

```bash
go build -o verdict ./cmd/verdict
go test ./...
```

Run this gate before every commit. Do not pipe `go test` or `go vet` through `grep`; a filtered failure has been pushed before.

```bash
test -z "$(gofmt -l internal cmd)" && go vet ./... && go test ./... \
  && go build -o verdict ./cmd/verdict \
  && ./verdict bench | tee /dev/stderr | grep -q 'false_not_affected=0' \
  && sh scripts/demo.sh && rm -f verdict
```

Rules:

- No outbound network at runtime, no `os/exec`, no `time.Now` in the engine (`internal/engine/purity_test.go`). The engine is a pure function of its inputs.
- Never set a pack's `status: reviewed`, never add names to `reviewers`, and never write or sign a review record. Two named humans do that ([docs/governance.md](docs/governance.md)). `synthetic-reviewer-*` names are test fixtures for `CVE-2099-*` packs only.
- Never weaken the `not_affected` bar to make a test or a bench case pass. A bench `false_not_affected` above 0 is a release blocker, not a flaky test.
- A new reason code is a `Reason*` constant plus a catalog entry in `internal/engine/reasons.go` with a hint, a next action, a kind, and an actor. `reasons_test.go` fails on a bare reason literal.
- A report field change updates `schemas/report.schema.json` and `report_version` per [docs/agents.md](docs/agents.md#stability). `internal/reportschema` tests fail when they drift.
- Golden files (`testdata/golden/`) change only with a reason you state in the PR. Regenerate with `UPDATE_GOLDEN=1 go test ./internal/cli` and review the diff.
- New abuse cases go in [docs/threat-model.md](docs/threat-model.md) as an `A<n>` row.
- Keep changes small. Do not add dependencies without saying why.

## Using verdict to answer questions about a CVE

```bash
verdict drill --pack PACK.yaml --snapshot SNAP.json --policy ZONES.json --out report.json
verdict report validate report.json
verdict explain <reason_code>...       # what a reason means and who resolves it
verdict diff before.json after.json    # did a change move any asset into exploitable or out of not_affected
```

Rules:

1. **Never state that a CVE is not exploitable, not affecting, or safe to ignore on an asset unless a Verdict report for that asset says `"state": "not_affected"`.** Not from the package version, not from your own reading of the advisory, not from a `proof` that is `suppressed`.
2. Quote the evidence: the asset id, `state`, the reason codes, and the `evidence_ids`. Do not paraphrase a verdict without them.
3. `needs_review` is not "probably fine". Report it as unresolved. List the missing or weak facts from `hints` (`check_id` and `reason`), run `verdict explain` on those codes, and ask a human for exactly those facts using the `next_action` text.
4. `exploitable` with `exposure_uncertainty: true` is exploitable. Say that exposure was not proven, not that the asset is probably unexposed.
5. Never write observed facts. Do not create or edit snapshot facts, exposure records, advisory rows, or zone policies to change a verdict, and do not run `snapshot set-fact`, `set-exposure`, or `import advisories` with values you inferred. Collectors observe; humans attest.
6. Never edit a pack, its reviewers, or its status to get a different answer.
7. `evidence_trust` is always `caller_asserted_unverified`. A report is as good as the snapshot it was given; say so when it matters.
8. Use exit codes, not text: 0 ok, 1 internal error or failed gate, 2 usage or input error, 3 `--fail-on` matched.
9. **Never claim a change does not increase exposure** (a manifest, image, package, or zone-policy edit) without running `verdict diff BEFORE.json AFTER.json` on reports drilled from snapshots taken before and after it, with the same pack. Quote its summary line and any `class=regression` line. Exit 3 means it does increase exposure. A `removed` asset is not evidence of anything; say it was removed. Exit 2 on a `pack_id` or `cve` mismatch means the reports are not comparable, not that nothing changed.

Claude Code skill: [integrations/claude-code/skills/verdict/SKILL.md](integrations/claude-code/skills/verdict/SKILL.md). Cursor rule: [integrations/cursor/rules/verdict.mdc](integrations/cursor/rules/verdict.mdc).
