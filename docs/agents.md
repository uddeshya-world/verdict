# Using Verdict from coding agents and scripts

This is the machine contract: what Verdict writes, how it exits, which parts are stable, and how an agent (Claude Code, Codex, Cursor, a CI job) should read it. Rules for agents are in [AGENTS.md](../AGENTS.md) at the repository root.

Nothing here changes how a verdict is decided. An agent reads Verdict's output. It does not decide exploitability itself, and it does not write the facts Verdict decides from.

## Output contract

| Output | Where | Machine-readable form |
| --- | --- | --- |
| Drill report | stdout, or `drill --out FILE` | JSON, [schemas/report.schema.json](../schemas/report.schema.json) (Draft 2020-12, embedded in the binary) |
| OpenVEX | `drill --openvex FILE` | OpenVEX 0.2, [schemas/openvex.schema.json](../schemas/openvex.schema.json) |
| Per-asset and summary lines from `drill` | stderr | Text for people. Read the report instead |
| Command summaries (`pack`, `import`, `snapshot`, `bundle verify`, `bench`, `version`, `openvex validate`, `report validate`) | stdout | Text by default; one JSON object with `--json` |
| Reason catalog | `verdict explain CODE...` or `verdict explain --all` | JSON |
| Errors | stderr, one line `verdict: <message>` | Use the exit code, not the message text |

Check a report before acting on it:

```bash
verdict report validate --json report.json
```

`report validate` checks the schema and that every reason code in the report is in the reason catalog. The schema checks only that a reason looks like a code (`^[a-z][a-z0-9]*(_[a-z0-9]+)+$`); catalog membership is checked in Go so the list of codes lives in one place, `internal/engine/reasons.go`. A test fails when the schema and `engine.Report` disagree on any field or on which fields are required.

## Exit codes

| Code | Meaning | Examples |
| --- | --- | --- |
| 0 | Success | Drill finished (whatever the verdicts are, unless `--fail-on` matched); a validator found nothing wrong |
| 1 | Internal error or a failed gate | The engine could not evaluate; `bench` found a false `not_affected` or a state mismatch |
| 2 | Usage or input error | Missing flag, unreadable or invalid file, failed lint, failed `pack test`, invalid report or OpenVEX, unknown reason code in `explain`, unknown `--fail-on` value |
| 3 | Policy match | `drill --fail-on` matched at least one verdict. The report and OpenVEX were written first |

A drill that reports `exploitable` or `needs_review` still exits 0 unless you pass `--fail-on`.

## `drill --fail-on`

| Value | Exits 3 when any verdict is |
| --- | --- |
| `exploitable` | `exploitable` |
| `affected` | `exploitable` or `vulnerable_not_exposed` (OpenVEX `affected`) |
| `needs_review` | `needs_review` |
| `not_cleared` | anything other than `not_affected` |

All outputs are written before the exit. The stderr line names the policy and how many verdicts matched. The report bytes are the same with and without `--fail-on`.

## The report

Top level: `report_version`, `tool`, `kb_version`, `evaluation_time`, `pack_id`, `pack_sha256`, `policy_sha256`, `pack_status`, `cve`, `evidence_trust` (always `caller_asserted_unverified`), `verdicts`, `summary`. Optional: `kb_key_id` and `kb_created_at` (with `--kb`), and `invoked_by` (with `--invoked-by`; see [Agent guardrails](#agent-guardrails)).

Each verdict has `state` (`exploitable`, `vulnerable_not_exposed`, `not_affected`, `needs_review`), `vex_status`, `confidence`, `reasons` (decision codes), `hints` (`check_id`, `reason`, `hint` text), `leaves` (one per check with `value`, `confidence`, `observed`, `stale`, `reason`, `evidence_ids`), and `proof` when a sufficient false proof exists, including when it was suppressed (`suppressed`, `suppress_reasons`).

Read `state`. Do not derive a state from `tree_value`, `proof`, or `confidence`: a `proof` with `suppressed: true` is not a `not_affected`.

## Reason catalog

Every reason code a report can carry has a catalog entry:

```bash
verdict explain stale_evidence pack_not_reviewed
verdict explain --all
```

```json
{
  "command": "explain",
  "ok": true,
  "reasons": [
    {
      "code": "stale_evidence",
      "kind": "leaf",
      "hint": "Evidence for check {check} is older than evidence_max_age ...",
      "next_action": "Re-collect the evidence on the asset and re-run drill ...",
      "actor": "collector"
    }
  ]
}
```

| Field | Values |
| --- | --- |
| `kind` | `leaf` (one check), `decision` (the not_affected bar or tree), `exposure`, `error` |
| `hint` | The text the report carries. Leaf hints are templates: `{check}` is the check id, `{detail}` the detail, `{detail_q}` the quoted detail |
| `decision_hint` | Present only for a code that is also emitted as a decision reason with different text (`confidence_below_not_affected_bar`) |
| `next_action` | What resolves it, in one or two sentences |
| `actor` | Who can resolve it: `human`, `collector` (re-collect on the asset), `reviewer` (pack review), `agent`, `none` |

No current entry has actor `agent`. Resolving a reason means new evidence, a human decision, or a pack review, none of which an agent supplies.

## `--json` shapes

Every `--json` object has `command` (the subcommand path) and `ok`. Validators that take several files (`pack lint`, `pack hash`, `pack test`, `report validate`, `openvex validate`) write the object even on failure, with `ok: false` and an `error` per file, then exit 2. `pack lint` and `pack hash` stop at the first failing file, as their text forms do. Every other command writes its object only on success; on failure stdout is empty and the error is on stderr.

| Command | Fields after `command`, `ok` |
| --- | --- |
| `version` | `module`, `version`, `report_version` |
| `pack lint` | `files[]`: `file`, `ok`, `pack_id`, `error` |
| `pack hash` | `files[]`: `file`, `ok`, `pack_id`, `pack_sha256`, `error` |
| `pack test` | `files[]`: `file`, `ok`, `no_tests`, `tests[]` (`name`, `asset_id`, `state`), `error` |
| `pack review` | `pack_id`, `pack_status`, `reviewers[]`, `signatures_verified` |
| `pack check-reviews` | `packs`, `reviewed[]` (pack ids whose signed record verified), `errors[]` (written on failure too, then exit 2) |
| `openvex validate`, `report validate` | `files[]`: `file`, `ok`, `error` |
| `bench` | The scoreboard, the same document as `--out` (`cases`, `false_not_affected`, `state_mismatches`, `rows[]`, ...) |
| `import cyclonedx`, `import trivy` | `out`, `asset_id`, `packages`, `skipped`, `skipped_names[]` |
| `import jar`, `import host` | `out`, `asset_id`, `packages`, `facts`, `exposure`, `skipped` |
| `import k8s` | `out`, `cluster`, `assets`, `notes` |
| `import advisories` | `out`, `rows`, `matched`, `unmatched`, `facts` |
| `snapshot merge`, `snapshot set-fact`, `snapshot set-exposure`, `snapshot apply` | `out`, `edits`, `assets` |
| `bundle verify` | `kb_version`, `created_at`, `key_id`, `files` |
| `explain` | `reasons[]`: `code`, `kind`, `hint`, `decision_hint`, `next_action`, `actor` |

Empty optional strings (`error`, `pack_id`, `decision_hint`) are omitted. Notes, skipped items, and warnings stay on stderr in both modes. The bench `--json` is the scoreboard itself, not wrapped in `command`/`ok`; it predates this contract.

## Stability

- `report_version` is semver. A field added to the report is a minor bump (`0.2.0`); a field removed, renamed, or given a new meaning is a major bump. A wording change in a hint is neither: match on `reason` codes, never on hint text.
- This release writes `report_version` `0.1.0`. The schema in the same binary accepts `0.1.x`.
- `invoked_by` was added without a version bump because it is opt-in: it is written only when the caller passes `drill --invoked-by`, so every default report is byte-identical to before. A validator from a release before it rejects a report that carries it (the schema has `additionalProperties: false`); validate with the same binary that drilled.
- Reason codes are stable. A new code can be added in a minor release; `report validate` from that release knows it. Removing or renaming a code is a major change.
- The `--json` shapes follow the same rule: fields can be added, not removed or renamed, within a major version.
- Text output is for people and can change in any release. Scripts that parse it should move to `--json`.

## Agent guardrails

Three controls make it visible, and harmless to the `not_affected` bar, when an agent rather than a person or a collector touched the inputs.

### Actor kinds on snapshot edits

`snapshot set-fact`, `set-exposure`, and `apply` take `--actor-kind human|agent` (default `human`). The value is stored as `actor_kind` on the asset's `edits` record. **An agent must pass `--actor-kind agent`.**

- `--actor-kind agent` with `--basis observed` exits 2. An agent did not observe the asset, so its entry is attested. Since `high` already needs `observed`, an agent entry is at most `medium`, and `confirmed` is never accepted from an edit. An attested entry cannot reach the `not_affected` bar.
- `apply`: an entry may carry `"actor_kind"`; an entry without one takes `--actor-kind`. With `--actor-kind agent`, an entry that says `"actor_kind": "human"` is refused, so an agent's batch cannot launder entries as human.
- Belt and braces in the engine: a fact or exposure entry whose most recent edit record has `actor_kind: agent` is read as attested whatever its `basis` says (a hand-written snapshot). The leaf carries reason `agent_edit_not_observed` (actor `human`), and agent exposure is not usable exposure evidence, so exposure becomes unknown rather than narrowed. A later human record for the same fact or port is the latest edit and decides.
- Records written before actor kinds existed have no `actor_kind` and are read as human, so existing snapshots and reports are unchanged.

### Signed review records

A reviewer entry in a review record may carry `key_id` and `signature`: base64 Ed25519 over the exact bytes

```
verdict-pack-review/v1\n<pack_id>\n<pack_sha256>\n<reviewer name>\n
```

(`pack_sha256` is the content hash from `verdict pack hash`; the name is trimmed). Keys are the `bundle keygen` PEM format and `key_id` is the bundle key id of the public key.

```bash
verdict pack sign-review --pack P.yaml --key ~/my-review.key --reviewer "Full Name" \
  --statement "..." --reviewed-at 2026-11-13T10:00:00Z     # a human, on their own machine
verdict pack review --pack P.yaml --record R.json --reviewer-keys packs/reviewer-keys --require-signatures
verdict pack check-reviews     # CI: packs/, packs/reviews/<pack_id>/*.json, packs/reviewer-keys/
```

`pack review --reviewer-keys DIR` verifies every signed entry against `DIR/<key_id>.pub`; an unknown key, a key file holding a different key, one key for two reviewers, or a signature that does not verify exits 2. `--require-signatures` also refuses unsigned entries. `pack check-reviews` fails (exit 2) when a non-synthetic pack has `status: reviewed` without a record in which every reviewer's signature verifies. **Agents never run `sign-review`**, never write review records, and never add keys to `packs/reviewer-keys/`. See [governance](governance.md#signed-review-records).

### Invocation provenance

`drill --invoked-by STRING` stores `invoked_by` in the report: printable ASCII (0x20-0x7e), 1 to 128 characters, else exit 2. Agents set it (`claude-code`, `codex`, `verdict-mcp/<client name>`), so a report says it was produced at an agent's request. It is a label the caller chose, not an authenticated identity; it does not change any verdict. Without the flag the field is absent.

## How an agent should use Verdict

1. Run `verdict drill ... --invoked-by <your agent name> --out report.json` (with `--policy` for your zones), then `verdict report validate report.json`.
2. For each asset, quote `state`, the `reasons`, and the `evidence_ids` the claim rests on.
3. Say an asset is not affected only when its `state` is `not_affected`. `needs_review` is not safe and not unsafe; it means the evidence is missing or not good enough.
4. For `needs_review`, list the missing facts from `hints` (`check_id`, `reason`), run `verdict explain` on the codes, and ask a human for those facts with the `next_action` text. Do not supply them.
5. In CI, use `--fail-on` and the exit code instead of parsing text.

Integration files: [AGENTS.md](../AGENTS.md), [integrations/claude-code/skills/verdict/SKILL.md](../integrations/claude-code/skills/verdict/SKILL.md), [integrations/cursor/rules/verdict.mdc](../integrations/cursor/rules/verdict.mdc).
