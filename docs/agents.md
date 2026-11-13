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

Top level: `report_version`, `tool`, `kb_version`, `evaluation_time`, `pack_id`, `pack_sha256`, `policy_sha256`, `pack_status`, `cve`, `evidence_trust` (always `caller_asserted_unverified`), `verdicts`, `summary`.

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
| `pack review` | `pack_id`, `pack_status`, `reviewers[]` |
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
- Reason codes are stable. A new code can be added in a minor release; `report validate` from that release knows it. Removing or renaming a code is a major change.
- The `--json` shapes follow the same rule: fields can be added, not removed or renamed, within a major version.
- Text output is for people and can change in any release. Scripts that parse it should move to `--json`.

## How an agent should use Verdict

1. Run `verdict drill ... --out report.json` (with `--policy` for your zones), then `verdict report validate report.json`.
2. For each asset, quote `state`, the `reasons`, and the `evidence_ids` the claim rests on.
3. Say an asset is not affected only when its `state` is `not_affected`. `needs_review` is not safe and not unsafe; it means the evidence is missing or not good enough.
4. For `needs_review`, list the missing facts from `hints` (`check_id`, `reason`), run `verdict explain` on the codes, and ask a human for those facts with the `next_action` text. Do not supply them.
5. In CI, use `--fail-on` and the exit code instead of parsing text.

Integration files: [AGENTS.md](../AGENTS.md), [integrations/claude-code/skills/verdict/SKILL.md](../integrations/claude-code/skills/verdict/SKILL.md), [integrations/cursor/rules/verdict.mdc](../integrations/cursor/rules/verdict.mdc).
