# Condition pack format (v0.1)

Normative for this version: a file `verdict pack lint` accepts. YAML 1.1/1.2 features that execute or explode are out: aliases and anchors are rejected, duplicate keys are rejected, documents larger than 256 KiB are rejected, and unknown fields are rejected. The decoder is `gopkg.in/yaml.v3` with known fields enabled. It does not deserialize into arbitrary Go types.

`apiVersion` must be `verdict.dev/v1`. `kind` must be `ConditionPack`. Exactly one CVE id is allowed.

## Checks

Allowed `type` values:

| Type | Fact it reads | True when |
| --- | --- | --- |
| `package_version` | Inventory packages plus optional `advisory_fact` | A non-distro package is in an affected range, or a distro package's advisory fact is `affected` |
| `host_fact` | `key` | The fact equals `equals` |
| `config_value` | `key` | The fact equals `equals` |
| `env_var` | `key` | The fact equals `equals` |
| `process_listening` | `process.listening.<process>` | The fact is `true` |
| `process_running` | `process.running.<process>` | The fact is `true` |
| `file_exists` | `file.exists.<path>` | The fact is `true` |
| `manual_attestation` | `key` | The fact equals `equals`, and `expires_at` is present |

Every check requires `negation_justification`, one of the five OpenVEX labels. `package_version` also requires `absence_justification` for the complete-inventory, package-missing case (usually `component_not_present`).

`package_version` may also set `absence_contradicted_by`, a list of fact keys such as `process.listening.sshd`. If the inventory has no matching package but any listed fact on the asset is `true`, the check is unknown (`component_absent_but_in_use`) instead of an absence proof.

`package_version` may also set `aliases`, a list of purl patterns (no version, qualifier, or subpath; at most 32; no duplicates; none equal to a component or check pattern) for other names under which the same component ships, for example `pkg:generic/sshd`. An inventory package that matches an alias, exactly or by name similarity, and is not an exact component match is unknown (`distro_advisory_required` unless an observed advisory on its exact package URL decides it): never absent and never version-sorted. Aliases only widen what blocks an absence proof. They never make a check true or false by themselves, and they are part of the pack content hash. List only packages that ship the component: a client-only package is not an alias.

`tradeoff` is optional text. When a sufficient false proof includes that check, the verdict sets `mitigation_dependent` and copies the text into `impact_statement`, including on the OpenVEX document. Nothing in v0.1 re-evaluates that mitigation later.

There is no `missing_means: true`. An absent fact is `unknown`. v0.1 will not invent a vendor default. That includes LoginGraceTime and Log4j lookup settings: put the effective value in the snapshot or accept `needs_review`.

`process.listening.sshd` is the process socket table. A false value means no sshd socket was observed. It does not mean a connection to tcp/22 cannot reach sshd. systemd socket activation (`ssh.socket` on Ubuntu 22.10 and later) and inetd hold the port in PID 1 and start sshd on the first connection. A snapshot that records only "sshd is not running" must not set `process.listening.sshd` to false and stop there. The regreSSHion pack also reads `service.socket_activation.sshd`. That fact is true when such a unit would spawn sshd. The reachability branch is false only when both facts are observed false. A missing socket-activation fact leaves the branch unknown, so it cannot support `not_affected`.

`when_package` may further restrict a check (used for mitigations that the advisory says apply only inside a version range). If the matched package is outside that range, the check is false because the predicate does not hold, using the inventory observation. Lint requires a `when_package` check to sit under an odd number of `not` nodes, so "mitigation not applicable" cannot by itself be the proof of `not_affected`.

## Version schemes

`openssh_upstream` accepts only `MAJOR.MINORpREVISION` (for example `9.6p1`). A Debian revision is a parse failure, which is `unknown`, not "not vulnerable".

`maven` accepts a documented subset: dot-separated numeric segments and the qualifiers alpha, beta, milestone, rc, cr, snapshot, ga, final, release, sp. Other qualifiers, including distro rebuild suffixes, are `unknown`.

`semver` and `go` exist for generic upstream strings. `go` requires a leading `v`. Build metadata (`+...`) is rejected.

`deb`, `rpm`, and `apk` package URLs never use those schemes. Those coordinates, and a same-name package the pattern did not match, stay `unknown` with reason `distro_advisory_required` unless `advisory_fact` is a fresh observed fact whose `purl` equals that inventory package URL. The value is `affected`, `fixed`, or `not_affected`. `fixed` means a vendor fix was applied. `not_affected` means the package was never vulnerable. Those are different claims. A fact with no `purl` does not cover any package. One fact covers one package. The fact does not override a non-distro package. If any non-distro match is inside an affected range, the check is true even when a distro fact says `fixed` or `not_affected`. A falsifying advisory result requires every non-distro match to be outside the range and every distro or unmatched same-name package to have its own `fixed` or `not_affected` fact.

## Conditions

A condition node is exactly one of `ref`, `not`, `all_of`, `any_of`. Maximum depth 8. Maximum 64 nodes. Every `ref` must name a check. Empty groups are rejected.

## Exposure block

`port` and `proto` (`tcp` or `udp`). This block does not decide `not_affected` and does not name zones. Zone vocabulary is a site policy file passed to `verdict drill --policy`. The policy has `untrusted_zones` and `trusted_zones`. Comparison is case-insensitive. `unknown` is not a concrete zone. A reachable zone is untrusted only when it matches the policy's untrusted list, and trusted only when it matches the trusted list. Any other label, and a missing policy, is unknown exposure, which is exploitable with uncertainty. Zone labels on the asset are echoed and are not a substitute for an exposure observation. `examples/policy/lab-zones.json` is the policy the fixtures use. It is not your organization's list.

## Tests

`tests` entries are optional on drafts and required on synthetic reviewed packs in this repository. Paths are relative to the pack file. `verdict pack test` evaluates them in process.

## Rejected on purpose

`code_reachable`, `network_path`, `jar_class_present` as a byte scanner, `waf_rule_present`, `kernel_version`, probes, and any `runner:` or `exec:` field. Jar class presence is represented, when a pack needs it, as a `host_fact` the caller claims to have observed. The engine does not open zip files.
