# ADR 0006: No outbound calls on the evaluation path

## Status

Accepted for v0.1.

## Context

The design notes require air-gap operation: Verdict does not fetch packs or phone home. A later collector must reach internal addresses only, through one allowlist.

## Decision

- `drill`, `pack lint`, `pack test`, and `openvex validate` do not import a dialer.
- `internal/netpolicy` is the only package that is allowed to call `net.Dialer`. Its default policy has an empty allowlist and returns an error before dialing.
- Tests inject a fake dial function. They do not need a network namespace to prove the deny path, and they do not connect to external hosts.
- CI has no `schedule:` trigger. Tests do not download advisories.

## Consequences

A knowledge update is a file the operator already has. "Knowledge as of" is the `kb_version` string in the snapshot, echoed into the report. The tool does not check that the string is true or fresh.

A future HTTP collector that uses `http.Get` or `http.DefaultClient` directly is a bug. The purity test is a grep over imports, not a kernel policy. It will not catch a dependency that dials during `init`. Dependencies are currently Cobra, yaml.v3, and the JSON Schema library. Review of new dependencies includes "does init dial".

## Alternatives

Running the demo inside a network namespace in CI would be stronger and is not required to lock the current code, which has no dial site to sandbox. It remains a reasonable addition when a collector exists.
