# ADR 0007: What v0.1 deliberately leaves out

## Status

Accepted for v0.1.

## Context

The design notes describe a multi-phase product: collectors, 25 reviewed packs, a UI, a sandbox, Batfish, govulncheck, optional local LLM drafting, signed OCI bundles, FIPS builds. Building stubs that return success would let the README drift into claiming those features.

## Decision

v0.1 ships the evaluator, the pack lint, the snapshot loader, OpenVEX export, two draft CVE packs, synthetic fixtures, and the documents around them.

Explicitly deferred, with no partial implementation:

- Active exploits, confirmatory probes, and sandboxes. A failed probe must not become `not_affected`, and the way to guarantee that today is to have no probe runner.
- LLM drafting. Drafts from a model would still be `status: draft`, but there is no client to call.
- Code reachability and network-path solvers.
- Distro feed ingestion. Callers may pass one advisory fact; the tool does not download RHSA, USN, DSA, Alpine, or SUSE data.
- Signing, encryption, authentication, audit hash chains.
- The Spring4Shell, xz, and IngressNightmare seed packs. They were not written because their preconditions were not encoded from primary documents in this change. An incomplete pack that guesses a falsifying check is worse than a missing file.

## Consequences

The roadmap in the README is a checklist with those items open. Phase 0 interviews are not something this repository can perform, and the kill-criterion in the design notes remains unresolved. That is recorded rather than marked done.

## Alternatives

Generating all five seed packs from memory was rejected where the advisory text was not checked in this session. regreSSHion and Log4Shell were encoded from the Qualys advisory and Apache's security page respectively, and the packs quote those limits in `limitations`.
