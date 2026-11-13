---
name: verdict-pack-author
description: Use when asked to write, draft, or propose a new Verdict Exploitability Condition Pack (ECP) for a CVE in the Verdict repository. Drafts a status draft pack from cited primary advisories, adds fixtures and bench cases, runs pack lint, pack test, and bench, and opens a pack-review PR for two human reviewers. Never promotes, reviews, or signs a pack.
---

# Verdict: drafting a condition pack

You are drafting a pack, not approving one. A pack you write is a claim about a vulnerability that two named humans must check against the sources before it can ever clear a host. Your job is to make that check fast and honest: cite every fact, encode only what the sources say, and leave everything you could not confirm visibly unknown.

**The correct outcome for your pack is `needs_review` on every asset that is not affected-and-proven.** A draft pack can never produce `not_affected`. Do not try to get one.

## Hard rules

1. `metadata.status: draft`, `reviewers: []`, always. Never set `reviewed` or `deprecated`, never add a reviewer name, never use a `synthetic-reviewer-*` name on a real CVE.
2. Never run `verdict pack sign-review`, never create or touch anything in `packs/reviews/` or `packs/reviewer-keys/`, never generate or handle a reviewer key, never write a review record.
3. Never mark a fact `observed` that you did not observe with a collector, and never edit an existing snapshot's facts to change a verdict. Fixtures you add are new, labelled lab data for your pack only.
4. Never weaken an existing pack: do not edit another pack's ranges, checks, conditions, `limitations`, or tests, and do not change a bench case's `ground_truth` or `expect_state`. If you think an existing pack is wrong, say so in the PR body.
5. Every claim cites a source with a URL and the date you read it (`metadata.sources[].note`). Primary sources first: the vendor or upstream advisory, then its machine-readable record (OSV/JSON), then distro trackers, then NVD. A claim you took from memory is labelled as such in `limitations` and in the PR, never presented as sourced.
6. Unknown stays unknown. No defaults (`missing_means` does not exist), no "probably". A precondition you cannot observe from inventory is a fact that is absent until a collector observes it.
7. `bench` must report `false_not_affected=0` and `state_mismatches=0`. A non-zero count is a blocker, not a flaky test. Never change engine code to make your pack pass.
8. Only fetch public advisory pages (read-only GETs). Do not run exploits or PoCs.

## Workflow

1. **Collect sources.** Open the upstream advisory and its JSON/OSV record. Write down, with quotes: affected range, first fixed version, every precondition (configuration, feature, platform, privilege), every mitigation with its tradeoff, and what the advisory says does *not* protect you. Then distro trackers for backports, if you are allowed to read them; if not, say so.
2. **Decide if the check types can express it honestly.** The closed set is in `internal/pack/pack.go` (`package_version`, `host_fact`, `config_value`, `env_var`, `process_listening`, `process_running`, `file_exists`, `manual_attestation`). Read `docs/pack-format.md`. A precondition that cannot be written as one of these must either stay out of the tree (it then never clears anything) or become a fact that is unknown unless observed. If the pack would have to guess, pick a different CVE and explain why.
3. **Write the pack** in `packs/draft/ecp-<cve-lowercase>-<component>.yaml`:
   - `package_version` with the upstream range on non-distro purls; `advisory_fact: advisory.<cve_underscored>.status` for deb/rpm/apk (never sort a distro revision against an upstream range).
   - One check per precondition, each with a `negation_justification` that is true to the source (code present but unreachable is not `vulnerable_code_not_present`).
   - Mitigations under `not`, with the `tradeoff` text from the source.
   - `limitations`: every gap, every unverified claim, and anything the exposure model gets wrong for this CVE.
   - `remediation.fix` and `interim` from the advisory's own recommendations.
4. **Add fixtures** as a new snapshot (for example `examples/snapshots/<name>-lab.json`) and declare `tests:` in the pack. Cover at least:
   - affected and exposed (or exposure unknown) → `exploitable`;
   - upstream fixed version → `needs_review` (draft);
   - each precondition unknown → `needs_review`;
   - each mitigation or falsified precondition → `needs_review` (draft);
   - package absent with a complete inventory → `needs_review` (draft);
   - a distro package without an advisory fact → `needs_review`.
5. **Add bench cases** to `bench/corpus.json` for the same assets. The bench scores drafts with the reviewed bar applied in memory, so a falsified-and-observed case is `not_affected` there. Label it `ground_truth: not_affected` only when the source says that evidence clears the CVE, and lock it with `expect_justification`. Label everything else `affected` or `unknown`. Add adversarial cases: attested instead of observed, non-canonical values, incomplete inventory.
6. **Run the gate** from the repository root and keep the output for the PR:

   ```bash
   go build -o verdict ./cmd/verdict
   ./verdict pack lint packs/draft/<your-pack>.yaml
   ./verdict pack test packs/draft/<your-pack>.yaml
   ./verdict bench --corpus bench/corpus.json      # must end false_not_affected=0 state_mismatches=0
   ./verdict pack hash packs/draft/<your-pack>.yaml # reviewers sign this content hash
   go test ./... && sh scripts/demo.sh              # goldens must not change
   ```

7. **Open the PR** on a branch, never on `main`, with the pack template and the `pack-review` label:

   ```bash
   gh pr create --base main --template pack.md --label pack-review
   ```

   Fill every section of `.github/PULL_REQUEST_TEMPLATE/pack.md`: the preconditions table with a source per row, what clears versus what only makes a host affected, the bench cases, the lint/test/bench output, and every claim you could not verify. Leave the reviewer section empty. Say in the first line that the pack is a draft written by an agent and needs two signed human reviews.

## What reviewers will check, so check it first

- The range matches the upstream advisory and the OSV record exactly, including the first fixed version.
- Each precondition has a source, and its `negation_justification` is what that source supports.
- Nothing you could not observe can make a check false.
- Distro packages need an advisory fact; nothing sorts a backported revision.
- `limitations` names what the pack does not model.

If a reviewer asks for a change, edit the pack and re-run the gate. Every edit changes the content hash, so earlier review records no longer apply. That is intended.
