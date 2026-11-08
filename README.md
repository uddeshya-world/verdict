# Verdict

Offline CVE exploitability triage for air-gapped vulnerability review. Verdict evaluates an evidence-backed condition pack against a local inventory snapshot and writes a deterministic JSON verdict plus an OpenVEX document. It does not scan your network, run exploits, or send telemetry.

**Author:** Uddeshya Kumar
**License:** Apache-2.0
**This tree:** v0.1 foundation (a vertical CLI slice, not the full product described in the design notes)

Search terms this repository is meant to be found by: offline CVE exploitability, air-gapped vulnerability triage, evidence-backed OpenVEX.

## What you can run today

One static Go binary:

1. Lint an Exploitability Condition Pack (typed checks only; unknown fields and check kinds are rejected).
2. Evaluate that pack against a local JSON snapshot of packages, facts, and exposure observations.
3. Emit a canonical JSON report, a one-line funnel count, and an OpenVEX 0.2 document. `openvex validate` uses the upstream schema embedded in the binary, so it does not depend on the working directory.

The engine is a pure function of the pack bytes, the site zone policy, the snapshot, an explicit evaluation time, and a knowledge-bundle version. The same inputs produce byte-identical output. The process does not open sockets.

## What this is not

This repository is a foundation, not a finished fire-drill product.

- There is no scanner, no SSH or Kubernetes collector, no web UI, and no database.
- There are **no** signed knowledge bundles, **no** encryption at rest, and **no** authentication.
- There are **no** reviewed real-world CVE packs. The regreSSHion and Log4Shell documents under `packs/draft/` are drafts with an empty reviewer list. Draft packs cannot produce `not_affected`.
- Reviewed semantics are tested with explicitly synthetic packs (`CVE-2099-*`, `synthetic: true`, reviewers named `synthetic-reviewer-*`). Those names are fixtures, not people who reviewed a real advisory.
- No ASVS, FIPS, SLSA, or "25 reviewed packs" claim is made. Those items are not implemented.
- Sandbox probes, LLM drafting, Batfish, and code-reachability analysis are out of scope for v0.1 and are not partially implemented.
- Facts in the sample snapshots are demo data. A confidence value in caller JSON is an assertion by the caller, not proof that the evidence is authentic. See [docs/trust-boundary.md](docs/trust-boundary.md).

Market statistics and competitive claims in [docs/design-plan.md](docs/design-plan.md) are unvalidated design input. This README does not repeat them as findings.

## Quickstart

Requires Go 1.22.x (this module is developed with Go 1.22.2). No network is required after dependencies are cached.

```bash
go test ./...
go build -o verdict ./cmd/verdict
./verdict version
```

Offline demo (also exercised by `scripts/demo.sh` and by tests):

```bash
./verdict pack lint packs/draft/*.yaml packs/synthetic/*.yaml

./verdict drill \
  --pack packs/draft/ecp-cve-2024-6387-openssh.yaml \
  --snapshot examples/snapshots/regresshion-lab.json \
  --policy examples/policy/lab-zones.json \
  --author "Uddeshya Kumar" \
  --out /tmp/regresshion-report.json \
  --openvex /tmp/regresshion.openvex.json

./verdict openvex validate /tmp/regresshion.openvex.json

./verdict drill \
  --pack packs/draft/ecp-cve-2021-44228-log4j.yaml \
  --snapshot examples/snapshots/log4shell-lab.json \
  --policy examples/policy/lab-zones.json \
  --author "Uddeshya Kumar" \
  --out /tmp/log4shell-report.json \
  --openvex /tmp/log4shell.openvex.json

./verdict pack test packs/synthetic/ecp-synthetic-polarity.yaml
```

The drill reads `evaluation_time` and `kb_version` from the snapshot. Pass `--evaluation-time` and `--kb-version` only to override those explicit inputs. The CLI does not substitute the current clock.

`verdict import cyclonedx` and `verdict import trivy` read a JSON file you already have and write a snapshot. Packages without a package URL are skipped. A Trivy `Vulnerabilities` array is not copied, so a scanner's fixed/affected decision does not become an advisory fact. The inventory defaults to `attested` and `medium`. `verdict import advisories` merges a local file of `affected`, `fixed`, or `not_affected` rows. That path does not download a USN or RHSA feed.

A human-readable line per asset is written to stderr. The JSON report is the canonical record.

Expected regreSSHion demo outcomes (draft pack, so none of them are `not_affected`):

| Asset | State | OpenVEX status | Why |
| --- | --- | --- | --- |
| `lab-edge-exploitable` | `exploitable` | `affected` | Upstream 9.6p1, glibc, sshd listening, LoginGraceTime not 0, observed path from `internet` |
| `lab-socket-activated` | `exploitable` | `affected` | sshd is not in the process table, but `service.socket_activation.sshd` is true, so tcp/22 still reaches sshd |
| `lab-internal-only` | `vulnerable_not_exposed` | `affected` | Same preconditions, observed path only from `internal`. Still affected |
| `lab-unknown-exposure` | `exploitable` | `affected` | Asset zones say internal, but there is no exposure observation. Unknown exposure is reported as exploitable with `exposure_uncertainty: true` |
| `lab-missing-config` | `needs_review` | `under_investigation` | LoginGraceTime was not observed. The absent key is not treated as the default |
| `lab-mitigated-draft` | `needs_review` | `under_investigation` | LoginGraceTime 0 would falsify the tree, and the pack is draft, so `not_affected` is withheld |
| `lab-deb-looks-fixed` | `needs_review` | `under_investigation` | Debian package URL. Upstream version order is not used as backport proof |
| `lab-deb-advisory-fixed` | `needs_review` | `under_investigation` | Observed advisory fact says `fixed`, but a draft pack still cannot emit `not_affected` |
| `lab-stale-version` | `needs_review` | `under_investigation` | Package observation is older than the pack max age |
| `lab-incomplete-inventory` | `needs_review` | `under_investigation` | Inventory is not complete, so a missing package is not `component_not_present` |
| `lab-upstream-fixed-draft` | `needs_review` | `under_investigation` | Upstream 9.8p1 is outside the Qualys range, and the pack is still draft |
| `lab-low-confidence-musl` | `needs_review` | `under_investigation` | libc observation says not glibc at low confidence. Not sufficient for `not_affected` |
| `lab-inferred-not-listening` | `needs_review` | `under_investigation` | "sshd not listening" is marked inferred, so it is discarded. A missing socket-activation fact would also leave reachability unknown |

The synthetic reviewed pack is the one that is allowed to emit `not_affected`, and only in the fixture cases where the proof is sufficient. See [docs/reproducible-run.md](docs/reproducible-run.md).

## How a verdict is decided

Each check is `true`, `false`, or `unknown`, with a caller-asserted confidence and evidence ids.

The condition tree uses Kleene three-valued logic:

- `all_of` is false if any child is false; otherwise unknown if any child is unknown; otherwise true.
- `any_of` is true if any child is true; otherwise unknown if any child is unknown; otherwise false.
- `not` swaps true and false and keeps unknown.

`not_affected` is narrower than "the tree is false":

- The pack status is `reviewed`, at least two distinct reviewers are named, and the pack confidence ceiling is `high` or `confirmed`.
- A sufficient proof of false exists. One strict false branch is enough inside `all_of`. Inside `any_of`, every branch must be strict. `not` flips polarity, so a mitigation check that is observed true can falsify `not: <mitigation>`.
- Every leaf in that proof is `basis: observed` (not inferred or attested), confidence at least `high` after the ceiling, fresh at the evaluation time, and carries one shared OpenVEX justification. Mixed justifications do not get collapsed into a guessed label.
- Unknowns, incomplete inventory, stale or expired evidence, unsupported ecosystems, and unsupported version strings never count as that proof.

Exposure does not choose `affected` versus `not_affected`. If the tree is true, a zone listed in the site policy's `untrusted_zones` is `exploitable`, a zone listed in `trusted_zones` is `vulnerable_not_exposed` (OpenVEX `affected`), and a missing policy, a missing observation, or an unlisted zone is `exploitable` with explicit uncertainty. Matching ignores case. Packs do not contain zone names. An advisory fact names one package URL. `fixed` means a vendor fix. `not_affected` means that package was never vulnerable. Neither value clears a different package, and neither clears a non-distro package that is still inside the affected range.

Details and the alternatives that were rejected: [docs/adr/0002-not-affected-proof.md](docs/adr/0002-not-affected-proof.md).

## Architecture

```
cmd/verdict                 CLI (Cobra)
internal/logic              Kleene evaluation and sufficient-proof selection (no I/O)
internal/engine             checks, exposure, verdict derivation (no I/O, no clock)
internal/pack               strict YAML load and lint
internal/vercmp             upstream version schemes; distro types are not sorted
internal/export/openvex     OpenVEX 0.2 document
internal/netpolicy          deny-by-default dial wrapper for future collectors
internal/snapshot           strict JSON snapshot loader
```

Collectors, if they are added later, are required to dial through `internal/netpolicy`. The default policy allows no destinations. v0.1 does not call it on the drill path.

See [docs/architecture.md](docs/architecture.md).

## Packs in this repository

| Path | Status | Role |
| --- | --- | --- |
| `packs/draft/ecp-cve-2024-6387-openssh.yaml` | draft | regreSSHion preconditions from the Qualys advisory. Not reviewed |
| `packs/draft/ecp-cve-2021-44228-log4j.yaml` | draft | Log4Shell preconditions from Apache's advisory. Not reviewed. Does not cover CVE-2021-45046 |
| `packs/draft/ecp-cve-2022-22965-spring.yaml` | draft | Spring4Shell preconditions from the Spring announcement. Not reviewed. A Boot jar is not encoded as safe |
| `packs/draft/ecp-cve-2024-3094-xz.yaml` | draft | xz 5.6.0 and 5.6.1 sshd path from the oss-security report. Not reviewed |
| `packs/draft/ecp-cve-2025-1974-ingress-nginx.yaml` | draft | ingress-nginx admission path from the Kubernetes announcement. Not reviewed |
| `packs/synthetic/ecp-synthetic-polarity.yaml` | reviewed, synthetic | Fixture for proof polarity, exposure, and `not_affected` |
| `packs/synthetic/ecp-synthetic-polarity-draft.yaml` | draft, synthetic | Same tree as the reviewed fixture, to show draft suppression |
| `packs/synthetic/ecp-synthetic-mixed.yaml` | reviewed, synthetic | Disjunction whose branches disagree on justification |

Version ranges in the draft CVE packs are a typed encoding of the cited advisory text. They are not a back-port database. `pkg:deb`, `pkg:rpm`, and `pkg:apk` do not match those ranges by sorting the version string. They stay unknown until the snapshot carries an explicit advisory fact. See [docs/adr/0003-version-and-backports.md](docs/adr/0003-version-and-backports.md).

## Safety and limitations

- Caller-supplied JSON can be wrong. The engine will not upgrade it to "verified".
- `not_affected` means "not affected, based on the supplied evidence at the stated evaluation time", under the rules above. It does not mean safe, and it does not expire on its own in v0.1 beyond the evidence max-age check performed at that time.
- Effective configuration is whatever fact the snapshot already resolved. v0.1 does not parse `Include` or `Match` blocks, does not open JARs, and does not apply a vendor default when a key is absent.
- Unsupported check kinds are rejected at lint time. There is no escape hatch that executes pack content.
- The tool does not contact NVD, OSV, vendors, or exploit services. Freshness of a knowledge bundle is an input string you supply, not a lookup.

Threat model (design, with implemented versus planned controls separated): [docs/threat-model.md](docs/threat-model.md).

## Roadmap

Implemented in this foundation:

- [x] Public documentation, license, threat model, ADRs, contributor and reviewer policy
- [x] Go / Cobra CLI: `pack lint`, `pack test`, `drill`, `openvex validate`, `import`
- [x] Deterministic Kleene engine and strict `not_affected` proof
- [x] Strict pack loader and linter
- [x] Local snapshot input and offline demo
- [x] OpenVEX export validated against the schema embedded in the binary
- [x] Funnel summary counts on stderr and in the JSON report
- [x] Deny-by-default `netpolicy` package, with no runtime dial on the drill path
- [x] Unit, property, golden, schema, and purity tests

Not implemented (do not treat design-plan milestones as done):

- [ ] Phase 0 interviews
- [x] Draft seed packs for Spring4Shell, xz, and IngressNightmare, still unreviewed
- [ ] Any real-world pack with two human reviewers, fixtures built from images, or a signed bundle
- [x] Offline CycloneDX and Trivy JSON import. Scanner vulnerability lists are ignored
- [ ] Grype importer, SSH collector, Kubernetes collector
- [ ] Distro advisory feeds (RHSA, USN, DSA, Alpine, SUSE) as downloaded data. A local advisory file is the only input today
- [ ] Knowledge-bundle import, signature verification, customer trust roots
- [ ] Web UI, API, authn, audit log, SQLite/Postgres, ticket export, PDF
- [ ] CycloneDX VEX and CSAF VEX
- [ ] Sandbox, probes, watch mode, Batfish, govulncheck reachability, local LLM drafting
- [ ] FIPS build, SLSA provenance, release signing, Helm/packages

## Comparison

These projects are adjacent. This list is not a benchmark and is not a claim that Verdict is more accurate.

| Project | What it is for | How this repository relates |
| --- | --- | --- |
| Trivy, Grype, Syft, Nessus | Finding components and vulnerable versions | Not a scanner. v0.1 does not import their output yet. The design intent is to consume that kind of inventory later |
| OpenVEX / vexctl | VEX document format and tooling | Exports OpenVEX 0.2. Does not replace the specification |
| govulncheck | Go call-graph reachability | Not implemented |
| Nuclei | Request templates | Packs describe preconditions. v0.1 runs no probes and cannot express an exploit payload |
| Dependency-Track | Ingesting and showing VEX | No integration in v0.1. Whether a generated document suppresses findings there has not been tested |

## Layout

The directories follow the design plan where this slice has code (`cmd/verdict`, `internal/engine`, `internal/pack`, `internal/export/openvex`, `internal/netpolicy`, `schemas`, `docs`). Empty packages were not added for collectors, sandbox, UI, or a database.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md). Reviewer rule for packs: [docs/governance.md](docs/governance.md).
