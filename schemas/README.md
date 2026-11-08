# Schemas

## `openvex.schema.json`

Copy of the OpenVEX JSON Schema retrieved on 2026-11-08 from:

https://github.com/openvex/spec/blob/a68ccd19b15a9604d28ef66ebf33f27a772ba4ec/openvex_json_schema.json

Upstream commit `a68ccd19b15a9604d28ef66ebf33f27a772ba4ec` (2025-03-31). The OpenVEX specification is Apache-2.0. The file is stored in-tree so `verdict openvex validate` and the tests can run with no network.

This is the schema for documents we export. It is not a schema for condition packs.

## Condition packs and snapshots

Pack YAML is validated by `internal/pack` (`verdict pack lint`). Snapshot JSON is validated by `internal/snapshot`. Those loaders are the normative checks for v0.1: they reject unknown fields, which is the property we need, and they are versioned with the code that interprets the files. A second JSON Schema for the pack would drift.

`docs/pack-format.md` describes the pack fields in prose.
