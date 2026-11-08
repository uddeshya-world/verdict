# Condition pack format (v0.1)

Normative for this version: a file `verdict pack lint` accepts. YAML 1.1/1.2 features that execute or explode are out: aliases and anchors are rejected, duplicate keys are rejected, documents larger than 256 KiB are rejected, and unknown fields are rejected. The decoder is `gopkg.in/yaml.v3` with known fields enabled. It does not deserialize into arbitrary Go types.

`apiVersion` must be `verdict.dev/v1`. `kind` must be `ConditionPack`. Exactly one CVE id is allowed.

## Checks

Allowed `type` values:

| Type | Fact it reads | True when |
| --- | --- | --- |
| `package_version` | Inventory packages plus optional `advisory_fact` | A matching package is in an affected range, or the advisory fact is `affected` |
| `host_fact` | `key` | The fact equals `equals` |
| `config_value` | `key` | The fact equals `equals` |
| `env_var` | `key` | The fact equals `equals` |
| `process_listening` | `process.listening.<process>` | The fact is `true` |
| `process_running` | `process.running.<process>` | The fact is `true` |
| `file_exists` | `file.exists.<path>` | The fact is `true` |
| `manual_attestation` | `key` | The fact equals `equals`, and `expires_at` is present |

Every check requires `negation_justification`, one of the five OpenVEX labels. `package_version` also requires `absence_justification` for the complete-inventory, package-missing case (usually `component_not_present`).

There is no `missing_means: true`. An absent fact is `unknown`. v0.1 will not invent a vendor default. That includes LoginGraceTime and Log4j lookup settings: put the effective value in the snapshot or accept `needs_review`.

`when_package` may further restrict a check (used for mitigations that the advisory says apply only inside a version range). If the matched package is outside that range, the check is false because the predicate does not hold, using the inventory observation. Lint requires a `when_package` check to sit under an odd number of `not` nodes, so "mitigation not applicable" cannot by itself be the proof of `not_affected`.

## Version schemes

`openssh_upstream` accepts only `MAJOR.MINORpREVISION` (for example `9.6p1`). A Debian revision is a parse failure, which is `unknown`, not "not vulnerable".

`maven` accepts a documented subset: dot-separated numeric segments and the qualifiers alpha, beta, milestone, rc, cr, snapshot, ga, final, release, sp. Other qualifiers, including distro rebuild suffixes, are `unknown`.

`semver` and `go` exist for generic upstream strings. `go` requires a leading `v`. Build metadata (`+...`) is rejected.

`deb`, `rpm`, and `apk` package URLs never use those schemes. The check is `unknown` with reason `distro_advisory_required` unless `advisory_fact` is a fresh observed fact whose value is `affected` or `fixed`.

## Conditions

A condition node is exactly one of `ref`, `not`, `all_of`, `any_of`. Maximum depth 8. Maximum 64 nodes. Every `ref` must name a check. Empty groups are rejected.

## Exposure block

`port`, `proto` (`tcp` or `udp`), and `untrusted_zones`. This block does not decide `not_affected`. It classifies a true tree. Zone labels on the asset are echoed and are not a substitute for an exposure observation.

## Tests

`tests` entries are optional on drafts and required on synthetic reviewed packs in this repository. Paths are relative to the pack file. `verdict pack test` evaluates them in process.

## Rejected on purpose

`code_reachable`, `network_path`, `jar_class_present` as a byte scanner, `waf_rule_present`, `kernel_version`, probes, and any `runner:` or `exec:` field. Jar class presence is represented, when a pack needs it, as a `host_fact` the caller claims to have observed. The engine does not open zip files.
