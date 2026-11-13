<!--
Pack PR template. Use it for any new or changed condition pack:
  gh pr create --template pack.md --label pack-review
Derived from the regreSSHion review packet (notes, 2026-11-12). Fill every
section. Write "not checked" rather than leaving a claim implied.
-->

## Pack

- File: `packs/draft/ecp-...yaml`
- CVE:
- Pack id:
- Author (person or agent, and which skill/rule):
- Status: **draft** (this PR must not set `reviewed`, add reviewers, or add files under `packs/reviews/` or `packs/reviewer-keys/`)
- Content hash (`verdict pack hash <file>`): `pack_sha256=`

> If an agent wrote this pack, say so here. It needs two independent human reviews, each signed with the reviewer's own key, before a separate PR can promote it.

## Sources

One row per source actually read. Primary first. Mark anything older than 12 months and anything not opened yourself.

| # | Source (URL) | Kind (upstream advisory / OSV-JSON / distro tracker / NVD / other) | Published or last modified | Read on | Supports which claims |
|---|---|---|---|---|---|
| S1 | | upstream advisory | | | |
| S2 | | OSV/JSON record | | | |

Sources not consulted (and why):

## Checklist

### Affected range (from upstream)
- [ ] Affected range in `package_version.affected_ranges` matches the upstream advisory and its OSV/JSON record exactly (quote both).
- [ ] First fixed upstream version stated and cited.
- [ ] Disagreements with NVD or scanners listed (for example a different start or an inclusive end).
- [ ] Version scheme (`semver`, `maven`, `openssh_upstream`, `go`) parses every bound; strings it cannot parse stay unknown.

### Fixed versions, including distro backports
- [ ] deb/rpm/apk packages are never sorted against the upstream range; they use `advisory_fact`.
- [ ] Distro fixed versions per release, with tracker links (or "not checked"):

| Distro / release | Affected? | Fixed package version / advisory id | Source |
|---|---|---|---|
| | | | |

- [ ] Package names in `component.purls` / `purl_patterns` checked against each distro (or marked unverified). Bundled or vendored copies the inventory may miss are named in `limitations`.

### Preconditions, each mapped to a check
| Precondition (quote) | Source | Check id and type | Fact key | Observable by a collector here? | When false: `negation_justification` |
|---|---|---|---|---|---|
| | | | | | |

- [ ] Every precondition that inventory cannot show is a fact that is unknown until observed (no defaults).
- [ ] Every `negation_justification` is what the source supports (code present but unreachable is not `vulnerable_code_not_present`).
- [ ] Preconditions deliberately **not** encoded (they never clear) are listed in `limitations`.

### Mitigations
| Mitigation | Source | Check id (under `not`) | Tradeoff text | Vendor calls it a fix or a workaround? |
|---|---|---|---|---|
| | | | | |

### What evidence clears vs. what only makes a host affected
- Clears (only on a reviewed pack, only from observed, fresh, high-confidence evidence):
- Only makes a host affected or exploitable (never clears):
- Stays unknown:
- [ ] Exposure block fits the attack path (listening service and port, or a stated limitation if it does not).

### Bench cases
| Case id | Asset | ground_truth | expect_state | What it locks |
|---|---|---|---|---|
| | | | | |

- [ ] Cases cover: affected and exposed, upstream fixed, each unknown precondition, each mitigation, package absent with a complete inventory, incomplete inventory, distro package without an advisory fact, attested instead of observed, a non-canonical value.
- [ ] `ground_truth: not_affected` only where the source says that evidence clears; each has `expect_justification`.

### Gate output (paste)

```
verdict pack lint ...
verdict pack test ...
verdict bench --corpus bench/corpus.json   # bench cases=N false_not_affected=0 state_mismatches=0
```

- [ ] `go test ./...` and `sh scripts/demo.sh` pass; goldens unchanged.
- [ ] No existing pack, test, or bench label was weakened.

## Open questions for reviewers

-

## Reviewer section (humans only; leave blank)

<!-- Agents: do not fill this section, do not tick these boxes, do not add names. -->

Each reviewer works independently from their own checkout, opens every primary source themselves, and records PASS / FAIL / UNSURE with a link or quote. Promotion happens in a separate PR after both records verify with `verdict pack review --pack <file> --record <record> --reviewer-keys packs/reviewer-keys --require-signatures`.

| # | Check | Reviewer 1 | Reviewer 2 |
|---|---|---|---|
| 1 | Affected range and fixed version match the primary sources | | |
| 2 | Distro table verified against live trackers | | |
| 3 | Each precondition and its justification match the source | | |
| 4 | Mitigations and tradeoffs match the source | | |
| 5 | Nothing unobservable can clear a host | | |
| 6 | `limitations` and `remediation` make no safety claim the sources do not | | |
| 7 | `pack lint`, `pack test`, `bench` run locally | | |
| 8 | `pack_sha256` recomputed locally matches the one signed | | |

Reviewer 1 (name, key id, date):
Reviewer 2 (name, key id, date):
