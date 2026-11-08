# Architecture (v0.1)

Verdict v0.1 is one command-line program. Evaluation is a pure function. I/O happens only in the CLI and the loaders, before the engine runs, and when the CLI writes the report the engine already produced.

```
snapshot JSON ──▶ snapshot.Load ──┐
pack YAML ──────▶ pack.Load/Lint ─┼─▶ engine.Evaluate ─▶ canonical JSON
explicit time, kb version ────────┘         │
                                             ├─▶ OpenVEX document
                                             └─▶ (no sockets, no time.Now)
```

## Components that exist

| Package | Responsibility |
| --- | --- |
| `cmd/verdict`, `internal/cli` | Cobra commands. Passes explicit inputs through. Exit 2 on usage or lint failure |
| `internal/pack` | Size-limited YAML parse. Rejects aliases, duplicate keys, unknown fields, unknown check kinds, dangling refs, excessive condition depth |
| `internal/logic` | Kleene `all_of` / `any_of` / `not` and selection of a sufficient false proof |
| `internal/engine` | Turns facts into leaves, classifies exposure, applies the reviewed-pack rule |
| `internal/vercmp` | Parses a few upstream schemes. Returns an error, which the engine maps to unknown, when a string is outside the scheme |
| `internal/export/openvex` | Builds an OpenVEX 0.2 document and validates it with `schemas/openvex.schema.json` |
| `internal/netpolicy` | The only package allowed to dial. Default allowlist is empty. Nothing in v0.1 calls `Dial` |
| `internal/canonjson` | `encoding/json` with HTML escaping disabled and stable struct order, trailing newline |

## Components that do not exist yet

The design notes name a server, a React UI, collectors, a knowledge-bundle store, a sandbox, ticket exporters, and an audit log. Those directories were not created as empty shells. Adding one means implementing the behavior and the threat-model row that goes with it, not a stub that returns success.

## Determinism

Banned in engine and logic code, and checked by test:

- `time.Now` and any other clock read
- `net`, `net/http`, and `os/exec`
- map iteration leaking into output order (outputs are structs and sorted slices)

`pack_sha256` is the SHA-256 of the pack file bytes the operator passed in. Changing whitespace changes the digest and therefore the OpenVEX document id. The verdict states themselves depend on the decoded pack, not on key order in the file.

## Evaluation pipeline

1. Reject a snapshot whose `evidence_trust` is anything other than `caller_asserted`.
2. For each asset, evaluate each check against facts. Stale, expired, future-dated, inferred, and unparsable observations become `unknown` leaves. They are not silent falses.
3. Evaluate the condition tree.
4. Derive the state. Exposure runs only when the tree is true.
5. Sort assets, reasons, hints, and evidence ids. Marshal.

The same pipeline is what `verdict pack test` uses for the `tests:` entries in a pack.
