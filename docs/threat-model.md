# Threat model (v0.1 design)

This is the Phase-1 threat-model deliverable scoped to the code that exists today, plus the threats the design notes assign to later components. It is a design document. It is not an OWASP ASVS assessment, not a penetration test, and not a statement of compliance with any control framework.

Method: assets, trust boundaries, and abuse cases, each marked **implemented** or **planned / not present**.

## System under consideration

An operator runs `verdict` on a machine they control, against a pack file and a snapshot file, and receives a JSON report and an OpenVEX document. There is no daemon, no account, and no remote endpoint.

## Assets

| Asset | Why it matters | In v0.1 |
| --- | --- | --- |
| Verdict output | A wrong `not_affected` can close a real exposure. A wrong `exploitable` wastes response time. The first is treated as the worse failure | Produced locally |
| Snapshots | An inventory of versions, config, and exposure. Sensitive if it describes a real environment | Caller files. Examples are synthetic |
| Packs | A malicious or mistaken pack can encode a false precondition | Data, linted, not signed |
| Host running the CLI | Compromise of this host can change inputs or outputs | Out of scope of the tool; no privilege boundary is claimed |

## Trust boundaries

1. **Operator → CLI.** The operator can pass any file. The CLI's job is to refuse malformed packs and to apply the verdict rules, not to authenticate the operator.
2. **Snapshot → engine.** Facts are untrusted claims. See `docs/trust-boundary.md`. **Implemented:** non-`caller_asserted` trust labels are rejected; inferred facts do not falsify; confidence is not raised; the report repeats the unverified label.
3. **Pack → engine.** Packs are untrusted data. **Implemented:** closed set of check types, no execution, structural limits. **Not implemented:** signatures, reviewer keys, customer re-signing.
4. **CLI → network.** **Implemented:** the drill path has no dialer. `internal/netpolicy` denies every address unless a future caller passes an allowlist. **Not implemented:** an OS-level egress firewall, which this user-space process cannot install by itself.
5. **Tool → production systems.** **Implemented by absence:** no collector, no probe, no sandbox. The tool cannot reach production unless the operator uses it as a generic program outside these commands.

## Abuse cases

| ID | Abuse | Consequence | v0.1 response |
| --- | --- | --- | --- |
| A1 | Snapshot omits a vulnerable package and marks inventory complete at high confidence | False `not_affected` on a reviewed pack, if every other proof leaf is also strict | **Accepted residual.** Authenticity is outside the engine. Draft packs still cannot emit `not_affected`. Documented in the trust boundary |
| A2 | Snapshot sets confidence to `confirmed` without having observed anything | Same as A1 | **Accepted residual.** Same documentation. The field is caller-asserted |
| A3 | Distro package version is sorted against an upstream range and declared fixed | The common backport false-negative | **Implemented:** `deb` / `rpm` / `apk` never take the version-sort branch. Missing advisory → unknown |
| A4 | Absent config key is filled with a vendor default that clears the finding | False `not_affected` | **Implemented:** absent facts are unknown |
| A5 | Stale "we patched this" fact | False `not_affected` after drift | **Implemented:** observations outside `evidence_max_age`, or with `expires_at` at or before evaluation time, become unknown. A future `observed_at` is also unusable |
| A6 | Draft or single-reviewer pack used to close findings | False confidence in an unreviewed encoding | **Implemented:** `not_affected` requires status `reviewed` and two distinct reviewer strings, and a ceiling of at least high. Repository policy additionally forbids non-synthetic reviewed packs in-tree |
| A7 | `any_of` false because one branch is false and another is unknown | Kleene value is unknown, but a naive "any false leaf" walk would say not affected | **Implemented:** disjunctions require every branch |
| A8 | Negated mitigation counted with the wrong polarity | Mitigation present treated as vulnerable, or mitigation absent treated as proof of safety | **Implemented:** `not` flips polarity; tests cover nested `not` / `all_of` / `any_of` |
| A9 | Two falsifying branches with different OpenVEX justifications | A single guessed justification misstates why | **Implemented:** mixed justifications stay `needs_review` |
| A10 | Unknown exposure labeled not affected, or internal-only labeled not affected | Understates lateral movement | **Implemented:** exposure never selects `not_affected`. Unknown exposure on a true tree is `exploitable` with `exposure_uncertainty`. Internal-only is `vulnerable_not_exposed` and OpenVEX `affected` |
| A11 | YAML anchor bomb or unknown field smuggles a check | Parser DoS or silent ignore | **Implemented:** aliases rejected, node and depth limits, duplicate keys rejected, unknown fields and check kinds rejected |
| A12 | Pack contains a shell command or probe and the CLI runs it | Remote code execution via untrusted pack | **Implemented:** no such field; probes are not representable |
| A13 | CLI phones home with inventory | Data leaves an air-gapped host | **Implemented** on the current command set: no dial. A test walks production imports |
| A14 | Demo snapshot is mistaken for a real assessment | Wrong operational decision | **Implemented** in documentation and in `evidence_trust`. Examples use `lab-` and `syn-` ids |
| A15 | Malicious reviewed pack from a future distribution channel | Systematic false `not_affected` | **Planned.** Not mitigated by signatures, because signing is not built. In-tree policy is a review rule, not a technical control against a pack the operator passes by path |
| A16 | Tool database of exploitable hosts is stolen | Map of weaknesses | **Not applicable.** No database is implemented. Reports written to disk have the sensitivity of their inputs; the CLI does not encrypt them |
| A17 | Secrets in a snapshot land in the report | Disclosure via the JSON the operator asked to write | **Partial.** The engine copies evidence ids and fact values that a check compared, and it does not have a secret scanner. Do not put secrets in snapshots. There is no log file |
| A18 | Dependency confusion or a compromised module at build time | Malicious binary | **Partial.** `go.sum` pins modules for this commit. There is no signed release and no SLSA provenance |
| A19 | `time.Now` makes two runs disagree or hides staleness | Non-reproducible audit | **Implemented:** evaluation time is a required explicit input |
| A20 | Active exploit or "confirmation" probe against production | Outage or compromise, and a policy violation for this project | **Implemented by absence.** No probe type, no sandbox, no production target flag |

## Planned controls (not built)

These appear in the design notes and are recorded so readers do not assume they exist:

- Signed packs and signed knowledge bundles, customer trust roots, re-signing
- Read-only collectors with a command allowlist
- Encryption at rest, authentication, authorization, audit log
- SBOM and provenance for the Verdict binary itself
- Sandbox isolation for any future confirmatory probe
- A benchmark suite with a measured false-`not_affected` rate on real images

No item above is "partially certified".

## Out of scope

Physical access to the operator workstation, malicious Go toolchain, and vulnerabilities in third-party products that the draft packs describe. The draft packs are not detection signatures and are not safe to treat as a scanning policy by themselves.
