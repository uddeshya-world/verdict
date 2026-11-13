---
name: verdict
description: Use when asked whether a CVE is exploitable or affects a host, container, or estate, and a Verdict pack and snapshot are available, or when reading a Verdict drill report. Runs the offline verdict CLI and reports only what the report proves.
---

# Verdict: evidence-backed CVE exploitability

Verdict is an offline CLI that decides, per asset, whether a CVE is `exploitable`, `vulnerable_not_exposed`, `not_affected`, or `needs_review`, from a condition pack and a local snapshot. It never emits a false `not_affected`: that state needs observed, fresh, high-confidence evidence and a pack reviewed by two humans. Your job is to run it and relay what it proves, not to decide exploitability yourself.

## Rules

1. Never say a CVE is not exploitable, not affecting, or safe on an asset unless a Verdict report for that asset has `"state": "not_affected"`. Your own reading of versions or advisories does not count, and neither does a `proof` with `"suppressed": true`.
2. Quote the asset id, `state`, the reason codes, and the `evidence_ids` for every claim.
3. `needs_review` means unresolved, not safe. List the facts from `hints` (`check_id`, `reason`), run `verdict explain` on those codes, and ask a human for exactly those facts with the `next_action` text.
4. `exploitable` with `exposure_uncertainty: true` is exploitable; exposure was not proven either way.
5. Never write observed facts: do not create or edit snapshot facts, exposure, advisory rows, or zone policies, and do not run `snapshot set-fact`, `snapshot set-exposure`, or `import advisories` with values you inferred.
6. Never edit a pack, its `reviewers`, or its `status`, and never invent reviewer names.
7. Use exit codes: 0 ok, 1 internal error or failed gate, 2 usage or input error, 3 `--fail-on` matched.

## Commands

```bash
# Evaluate one pack against a snapshot; the report is the answer.
verdict drill --pack PACK.yaml --snapshot SNAP.json --policy ZONES.json --out report.json

# Check the report before reading it (schema + reason catalog).
verdict report validate --json report.json

# What a reason means, what resolves it, and who can (human, collector, reviewer).
verdict explain missing_fact pack_not_reviewed
verdict explain --all

# CI gate: exit 3 if anything is exploitable or vulnerable_not_exposed.
verdict drill --pack PACK.yaml --snapshot SNAP.json --policy ZONES.json --out report.json --fail-on affected

# Machine-readable summaries.
verdict pack lint --json PACK.yaml
verdict version --json
```

Reading a report: use `verdicts[].state` and `summary`; `hints[]` lists what is missing per check; `leaves[].evidence_ids` names the evidence. The full contract is `docs/agents.md` in the Verdict repository.

## Answer template

For each asset: `<asset_id>: <state> (vex <vex_status>, confidence <confidence>). Reasons: <codes>. Evidence: <evidence_ids>.` For `needs_review`, add: `Needs from a human: <fact or action per hint>.`
