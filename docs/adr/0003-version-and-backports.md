# ADR 0003: Upstream version order is not distro backport correctness

## Status

Accepted for v0.1.

## Context

A large class of scanner false positives, and a smaller class of dangerous false negatives, comes from comparing a distribution package's version string to an upstream range. Distributions patch without moving the upstream version, and they also prefix epochs and revisions (`1:9.8p1-3ubuntu13`) that do not mean "upstream 9.8p1, therefore fixed".

The design notes call distro advisory feeds the backlog item that fixes this. Those feeds are not in this tree.

## Decision

- Package URL types `deb`, `rpm`, and `apk` never use `vercmp`. The leaf is unknown with reason `distro_advisory_required` unless the pack's `advisory_fact` is present and usable.
- A package whose **name** matches a pattern but whose type or namespace does not (for example `pkg:rpm/.../log4j-core` against a `pkg:maven` pattern) is not `component_not_present`. The leaf is unknown until an advisory fact names that coordinate. Absence is only for a complete inventory that contains no package of those names.
- Usable means the fact exists, is not stale, is not inferred, and its value is `affected` or `fixed`. A stale advisory does not fall through to version sorting.
- `pkg:generic` with scheme `openssh_upstream` parses only `MAJOR.MINORpREVISION`. Any other string, including an Ubuntu revision glued onto a generic purl, is unknown.
- `maven` parses a documented subset. Qualifiers outside that subset are unknown, so a rebuild suffix is not ordered as if it were upstream.
- A scheme the pack names and this binary does not implement is a lint error, not an unknown at runtime. A version string that does not parse is an unknown at runtime.
- Matching an upstream range can still produce a **true** "vulnerable build" leaf for `pkg:generic` / `pkg:maven` / `pkg:golang`. That can over-report `affected`. It cannot, by itself, clear a distro package.

## Consequences

The regreSSHion demo asset that carries a Debian purl stays `needs_review` even when the version text contains `9.8p1`. An asset with an explicit observed `advisory...=fixed` fact falsifies the version check, and the draft pack still withholds `not_affected`.

Callers can lie by labeling a distro build as `pkg:generic/openssh@9.8p1`. The engine trusts the purl type it is given. That limitation is part of the trust boundary, not something version sorting can repair.

## Alternatives

Embedding a partial Debian version comparison and "doing our best" was rejected. A best-effort backport answer that sometimes returns false is the unsafe shortcut.
