# verdict-bench

Ground truth for the packs in this repository. `verdict bench` fails when a fixture that is not labeled `not_affected` is scored `not_affected`.

Draft CVE packs stay draft. The bench copies each pack in memory, sets `status: reviewed`, and attaches two `synthetic-reviewer-*` names so the decision bar is the one a reviewed pack would use. Those names are not written to the pack and they are not a review of a real CVE. A real promotion still needs two human reviewers and a public review record. See `docs/governance.md`.

`ground_truth` is one of:

| Label | Meaning |
| --- | --- |
| `affected` | The vulnerable condition holds. Exposure may still change exploitable versus vulnerable_not_exposed. |
| `not_affected` | A sufficient falsification under this pack's stated preconditions is the correct claim. |
| `unknown` | The evidence does not support a clear. `not_affected` here is a failure. |

`expect_state` locks the state, so a case that quietly degrades is also a failure. A `not_affected` case with `require_mitigation_dependent` fails when the tradeoff is missing.

Adversarial fixtures from review:

- `regresshion/lab-socket-activated` — sshd is not running, socket activation is true, still exploitable.
- `regresshion/import-complete-skips-openssh` — CycloneDX names openssh-server without a package URL. `--complete` must reject the file.
- `regresshion/wrong-advisory-version` — `fixed` on a different package URL does not clear the installed build.
- `regresshion/import-syft-rocky-epoch-complete` and `import-trivy-rocky-epoch-complete` — syft's OS component and rpm epochs (`epoch=` qualifier, or Trivy's split Epoch/Version/Release) no longer block `--complete`, and the epoch package is still evaluated.
- `regresshion/import-advisory-no-qualifiers-fixed` — a USN-style row without qualifiers lands on syft's qualified package URL.
- `regresshion/import-advisory-distro-mismatch-dropped` and `-rejected` — a 22.04 `fixed` row does not clear a 24.04 package; strict import rejects the row.
- `xz/lab-xz-sshd-down` — xz 5.6.1 stays exploitable when sshd is down.
- `log4shell/lab-log4j-property-set` — log4j-core 2.14.1 with JndiLookup present stays exploitable when `formatMsgNoLookups` is true. Removing the class is still a valid mitigation.
- `regresshion/purl-*` — name case, trailing space, `openssh-portable`, and a deb name in another case stay in scope (needs_review, or exploitable with an `affected` advisory). `pkg:GENERIC` is an exact match.
- `regresshion/adv-conflict-*` — `fixed` and `affected` on two spellings of one package URL are needs_review in either order.

Every pack file under `packs/draft` and `packs/synthetic` must appear in the corpus. An import case must set `expect_state`. `import_advisories` applies an advisory file (rows use asset id `imported`) and `import_allow_unmatched` drops rows that match nothing.

Run from the module root:

```bash
go build -o verdict ./cmd/verdict
./verdict bench --corpus bench/corpus.json
```

CI runs that command. A non-zero exit fails the job.
