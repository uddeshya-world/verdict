# Security policy

Verdict v0.1 is an offline evaluator. It is not a security boundary by itself: the JSON snapshot is caller-supplied, packs are data, and this tree has no authentication, no encryption at rest, and no signed releases.

## Reporting a vulnerability

There is no security email address for this project. Do not invent one, and do not send reports to an unrelated maintainer address.

Use GitHub private vulnerability reporting on `uddeshya-world/verdict` if that feature is enabled for the repository. If it is not enabled, open a public GitHub issue that describes the defect without exploit payloads, without proof-of-concept code against third-party products, and without data from a real environment.

Please include the commit SHA, the pack or snapshot shape that triggers the bug, and whether you believe the bug can turn unknown or draft evidence into `not_affected`.

## What is in scope

- Logic that marks an asset `not_affected` without a sufficient observed proof, or from a draft pack.
- Logic that treats unknown exposure, a distro version string, stale evidence, or an unsupported check as `not_affected`.
- Loader acceptance of unexpected YAML types, aliases, duplicate keys, or unknown check kinds that changes evaluation.
- Any outbound network call on the `drill` or `pack` path.
- A sample file, test, or commit that contains a real secret or data from a private environment.

## What is out of scope for this tree

Sandbox escape, pack signing, and account takeover are out of scope because those components are not implemented. A report that the CLI trusts a local JSON file is acknowledged by `docs/trust-boundary.md`; a bypass of the documented trust rules still qualifies.

This project will not ship or accept active exploit payloads, scanners aimed at third parties, or "detection" code that attacks a host. Packs describe preconditions. They do not carry probes in v0.1.

## Supported versions

Only the default branch is maintained. There are no published releases yet. Do not treat a git commit as a signed release.
