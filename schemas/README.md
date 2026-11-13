# Schemas

## `openvex.schema.json`

Copy of the OpenVEX JSON Schema retrieved on 2026-11-08 from:

https://github.com/openvex/spec/blob/a68ccd19b15a9604d28ef66ebf33f27a772ba4ec/openvex_json_schema.json

Upstream commit `a68ccd19b15a9604d28ef66ebf33f27a772ba4ec` (2025-03-31). The OpenVEX specification is Apache-2.0. The file is stored in-tree and embedded in the `verdict` binary (`schemas/embed.go`). `verdict openvex validate` uses those bytes unless `--schema` names another file. Validation does not use the network and does not require this directory to be the working directory.

This is the schema for documents we export. It is not a schema for condition packs.

## `report.schema.json`

JSON Schema (Draft 2020-12) for the drill report, the machine contract that agents and scripts read ([docs/agents.md](../docs/agents.md)). Written for this project, Apache-2.0, embedded in the binary (`schemas/embed.go`). `verdict report validate FILE...` checks a report against it with no network and from any working directory.

Policy:

- The schema describes `engine.Report` exactly: every object has `additionalProperties: false`, and `required` lists exactly the fields without `omitempty`. `internal/reportschema` has a test that fails when the schema and the Go structs disagree, and every golden report is validated in `go test ./...` and in CI.
- Enumerations (`state`, `vex_status`, `confidence`, `pack_status`, `justification`, tree and leaf values) are spelled out in the schema.
- Reason codes are not enumerated in the schema. The schema checks their shape (`^[a-z][a-z0-9]*(_[a-z0-9]+)+$`); `verdict report validate` checks that each one is a key of the reason catalog in `internal/engine/reasons.go` (`verdict explain --all`). One list, so the schema cannot fall behind the engine.
- `report_version` is semver and the schema accepts the minor line it ships with (`0.1.x`). A field addition bumps the minor version and the schema in the same commit; a removal, rename, or change of meaning bumps the major version.

## Condition packs and snapshots

Pack YAML is validated by `internal/pack` (`verdict pack lint`). Snapshot JSON is validated by `internal/snapshot`. There is no JSON Schema for either; the report is the only Verdict-defined format with one, because agents and scripts consume it. Those loaders are the normative checks for v0.1: they reject unknown fields, which is the property we need, and they are versioned with the code that interprets the files. A second JSON Schema for the pack would drift.

`docs/pack-format.md` describes the pack fields in prose.
