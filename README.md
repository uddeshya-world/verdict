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

The drill reads `evaluation_time` and `kb_version` from the snapshot. Pass `--evaluation-time` and `--kb-version` only to override those explicit inputs. The CLI does not substitute the current clock for evaluation time. Snapshot files are capped at 256 MiB by default (about 10k real hosts); `drill`, `snapshot merge`, `pack test`, and every command that writes a snapshot (`import cyclonedx`, `trivy`, `jar`, `host`, `k8s`, `advisories`, and `snapshot merge`) take `--max-snapshot-bytes` (1 to 1 TiB) to change it. An oversized file is refused from its size before it is read, and output over the cap is refused instead of written. `import jar` also scans a zip entry whose name is not a known archive suffix when its first bytes are the zip header.

**Offline knowledge bundles.** On the connected machine: `verdict bundle keygen`, then `verdict bundle build --dir <packs and OSV records> --kb-version 2026.11.09 --created-at <RFC3339> --key priv.pem --out kb.tar`. Carry `kb.tar` and `pub.pem` across. On the air-gapped side: `verdict bundle install --bundle kb.tar --pubkey pub.pem --dir kb/`, then `verdict drill --kb kb/2026.11.09 --pubkey pub.pem --cve CVE-... --snapshot ... --policy ...`. The drill re-verifies the stored bundle, uses the pack for that CVE, and falls back to the bundle's OSV records when there is none. Installed versions are immutable. Signing proves where the knowledge came from, not that a pack is correct. With `--kb`, the report's `kb_version`, `kb_key_id`, and `kb_created_at` come from the signed manifest, and `--kb-version` is refused. A bundle whose `created_at` is more than 5 minutes after the machine's wall clock is refused (forgery or a wrong clock). One created after the snapshot's evaluation time but not in the future is allowed, so an older snapshot can be re-checked with newer knowledge; stderr says "kb is newer than the snapshot" and the report keeps both `kb_created_at` and `evaluation_time`. `--max-kb-age 30d` (or any Go duration) refuses one created longer ago than that, measured against the evaluation time. `bundle install` keeps `kb/LATEST`, which names the newest installed version by signed `created_at` and only moves forward; `drill --kb` refuses an older version unless you pass `--allow-older-kb`. `LATEST` is unsigned: it stops a drill pointed at a stale install by mistake, not someone who can write to `kb/`. If it is missing, the drill prints that the floor was not checked.

**No pack for this CVE yet?** `verdict drill --osv <record.json> --snapshot ... --policy ...` builds a version-only fallback in memory from local OSV records (download them on a connected machine, e.g. from osv.dev, and carry them in). It is always a draft with a low confidence ceiling. An in-range package is `affected`; an absent or out-of-range one is `needs_review`, never `not_affected`. Maven, npm, Go and crates.io ranges are compared. Distro ecosystems (Debian, Ubuntu, Alpine, Red Hat) are skipped and listed on stderr, because distro builds need an advisory fact. `--port`/`--proto` set the service to check exposure for; without them exposure is unknown and fails closed.

`verdict bench --corpus bench/corpus.json` scores every labeled fixture, including socket activation, a skipped CycloneDX component with `--complete`, an advisory for a different package URL, and the backdoored xz build with sshd down. It exits non-zero on a false `not_affected`. The reviewed bar is applied in memory. See [bench/README.md](bench/README.md).

`verdict import cyclonedx` and `verdict import trivy` read a JSON file you already have and write a snapshot. Packages without a package URL are skipped, and the summary line names every skipped package. A CycloneDX `operating-system` component without a package URL (syft always emits one for the distro release) is ignored with a note; it is not a package and does not block `--complete`. For rpm and deb, an epoch may sit in the `epoch=` qualifier while the version field spells it out (`4.9-8.el9?epoch=2` and `2:4.9-8.el9` agree). Trivy's split `Epoch`, `Version`, and `Release` fields are recomposed as `epoch:version-release` before they are compared with the package URL. A Trivy `Vulnerabilities` array is not copied, so a scanner's fixed/affected decision does not become an advisory fact. The inventory defaults to `attested` and `medium`. `--complete` is refused when any component was skipped.

`verdict import advisories` merges a local file of `affected`, `fixed`, or `not_affected` rows. That path does not download a USN or RHSA feed. A row can be written the way the advisory reads it (`pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10`). It lands on every inventory package on that asset with the same canonical type, namespace, name, and version, where an rpm/deb epoch may be in the version or in the `epoch` qualifier. The `arch` and `upstream` qualifiers are ignored. A `distro` qualifier on the row must equal the package's, so a 22.04 row never clears a 24.04 package; a row without `distro` matches any distro. Any other qualifier and the subpath must be equal. The fact is written on the package's exact package URL, and the command prints where each row landed. A row that matches no package fails the import with exit 2; `--allow-unmatched` drops such rows and lists them instead, except a row that is only a case, fullwidth, or lookalike spelling of an inventory package: that is always an error, because dropping it could leave a `fixed` sibling to clear the host. Two rows with different values for one key on one package, or on spellings that fold to one package, fail the import. Import canonicalizes package URLs by decoding percent-escapes and sorting qualifiers. `verdict snapshot merge` joins those snapshots when the evaluation time and knowledge-bundle version are the same.

`verdict import jar --input app.war [--input lib.jar ...]` opens JAR, WAR, EAR, and ZIP files in memory and recurses into nested archives such as `WEB-INF/lib`, `BOOT-INF/lib`, EAR modules, and nested `.zip` files (and other zip-based `.rar`, `.sar`, `.har`, `.aar`, `.jpi`, `.hpi` archives). Other archive formats found inside (`.tar`, `.tar.gz`, `.7z`, `.jmod`, and similar) are not read; each is listed as skipped, which refuses `--complete`. A `.zip` that holds no classes and no nested archives is a bundle of files, not a component, and is not skipped. Nothing is extracted to disk and nothing is fetched. Components come from `META-INF/maven/<group>/<artifact>/pom.properties`. A manifest is used only when its `Implementation-Title` is in a small fixed table. A WAR, EAR, or fat jar without its own coordinates counts as a scanned container, not a skip, when every nested library in it was identified. Any other unidentified archive is listed as skipped, and a version is never taken from a file name. `jar.class.org.apache.logging.log4j.core.lookup.JndiLookup` is `present` when the class is in any scanned archive, including a shaded jar without log4j-core coordinates (that copy's package is skipped, so the version stays unknown). It is `absent` only when every identified log4j-core copy has other log4j-core classes but not `JndiLookup`, and it is omitted when no log4j-core is found. A `JndiLookup.class` in any other package (a shading relocation such as `com/acme/shade/lookup/JndiLookup.class`), or a `jndi` entry in a `Log4j2Plugins.dat` plugin cache that names any class other than the canonical one, rules out `absent`: the fact is omitted (unknown) unless the canonical class is present. The canonical cache entry left behind by `zip -d` does not block `absent`. `absent` describes only the archives you passed. Another archive on the same classpath, such as an application server `lib` directory, may still carry the class. So `absent` is `high` only with `--complete`, which asserts every classpath archive was passed. Without it, `absent` is `medium`, which is below the `not_affected` bar. `runtime.jdk9_or_newer` is written only from `--java-version`, as an `attested` operator statement. Class-file versions are a compile target and are not read as the runtime. The inventory is `observed` and `high`, `complete` is false unless `--complete` is passed, and `--complete` is refused when anything was skipped. Evidence ids hash the archive bytes plus the path inside. Depth (4), entry count, per-entry size, and total uncompressed size are capped, and an entry name that is absolute or contains `..` refuses the whole import.

`scripts/collect-host.sh` is a POSIX shell script you run on a Linux host yourself, for example `ssh admin@host 'sh -s' < scripts/collect-host.sh > host.json`. Verdict never runs it and never connects to the host. It is read-only: it writes nothing but one JSON document on stdout, installs nothing, restarts nothing, parses `/etc/os-release` instead of sourcing it, and does not read private keys, `/etc/shadow`, or environment values. It lists dpkg, rpm, and apk packages as package URLs with `arch` and `distro` qualifiers (rpm epoch as an `epoch` qualifier, deb epoch in the version), the listening TCP ports, and five facts: `libc.family`, `process.listening.sshd`, `service.socket_activation.sshd`, `config.sshd.LoginGraceTime`, and `process.sshd.links_liblzma`. A fact the script could not observe is left out, not guessed. Without root, socket owners are hidden, so "sshd is not listening" and "no socket activation" are omitted. `LoginGraceTime` comes from `sshd -T`, or from a value written in `sshd_config` and its `Include` files, and is never the default of 120. `verdict import host --input host.json --out snap.json --asset-id ID --kb-version KB --evaluation-time T` turns that file into a snapshot. Facts and inventory are `observed` and `high` at the collection time, with an evidence id hashed from the file, and `complete` is false unless `--complete` is passed. `--complete` is refused when any package line was unparsed. Listening ports become exposure only with `--reachable-from ZONE`, which is your statement of who can connect. Without it, exposure stays unknown and fails closed. The output is caller-asserted like any snapshot (see [docs/threat-model.md](docs/threat-model.md) A25–A27).

`verdict import k8s` reads kubectl JSON that you exported with your own credentials, for example `kubectl get pods,services,ingresses,networkpolicies,deployments,daemonsets,statefulsets,validatingwebhookconfigurations -A -o json > cluster.json`. It never contacts the cluster. Pass `--input` once per file. Each Deployment, DaemonSet, StatefulSet, or unowned Pod becomes a `k8s_workload` asset with its images as `pkg:oci` package URLs. The inventory is always `complete: false`, because an image is opaque. An upstream `registry.k8s.io/ingress-nginx/controller` image with a clean `vX.Y.Z` tag also gets `pkg:generic/ingress-nginx@vX.Y.Z`. A digest-only, mirrored, or oddly tagged image gets no app version, so the version check stays unknown. `ingress_nginx.admission_webhook` is `true` when a ValidatingWebhookConfiguration points at a Service selecting the controller or any controller argument mentions `validating-webhook`. It is `false` only when every controller container has an explicit command or args without that flag, webhook objects are in the input, every one resolves, and none reaches the controller. A `sh -c` wrapper or an image-default entrypoint hides the real arguments, so the fact is omitted, as it is in every other case. Exposure comes from Services and Ingresses through selectors. ClusterIP and declared container ports are zone `cluster-internal`, which your site policy has to classify (for CVE-2025-1974 the pod network is the attack path, so do not list it as trusted lightly). LoadBalancer, NodePort/hostPort, and Ingress backends take the zones from `--untrusted-zone-for-loadbalancer`, `--untrusted-zone-for-nodeport`, and `--untrusted-zone-for-ingress`. A missing flag writes `unknown`, which is treated as exposed. NetworkPolicy is not used to narrow exposure in this version.

```sh
./verdict import k8s --input examples/k8s/cluster.json --out /tmp/k8s.json --cluster lab \
  --kb-version demo-2026.11.08 --evaluation-time 2026-11-08T12:00:00Z --observed-at 2026-11-08T11:00:00Z \
  --untrusted-zone-for-loadbalancer internet --untrusted-zone-for-ingress internet
./verdict drill --pack packs/draft/ecp-cve-2025-1974-ingress-nginx.yaml --snapshot /tmp/k8s.json --policy examples/policy/lab-zones.json
```

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
- [x] Go / Cobra CLI: `pack lint`, `pack test`, `drill` (pack, OSV fallback, or installed bundle), `openvex validate`, `import`, `bench`, `bundle keygen/build/verify/install`
- [x] Deterministic Kleene engine and strict `not_affected` proof
- [x] Strict pack loader and linter
- [x] Local snapshot input and offline demo
- [x] OpenVEX export validated against the schema embedded in the binary
- [x] Funnel summary counts on stderr and in the JSON report
- [x] Deny-by-default `netpolicy` package, with no runtime dial on the drill path
- [x] Unit, property, golden, schema, and purity tests
- [x] `verdict bench` ground-truth gate. A false `not_affected` fails CI. Draft packs are scored with an in-memory reviewed bar and are not promoted.

Not implemented (do not treat design-plan milestones as done):

- [ ] Phase 0 interviews
- [x] Draft seed packs for Spring4Shell, xz, and IngressNightmare, still unreviewed
- [ ] Any real-world pack with two human reviewers. `verdict pack review` checks a record against the pack bytes and does not edit the pack. regreSSHion stays draft
- [ ] Fixtures built from images, or a signed bundle
- [x] Offline CycloneDX and Trivy JSON import. Scanner vulnerability lists are ignored
- [x] Offline JAR/WAR/EAR inspection (`import jar`) for Maven coordinates and the Log4j `JndiLookup` class
- [x] Read-only Linux host collector script (`scripts/collect-host.sh`) and `import host`
- [x] Offline Kubernetes import from kubectl JSON. NetworkPolicy does not narrow exposure
- [ ] Grype importer, live Kubernetes collector
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
