// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package schemas holds the JSON Schemas embedded in the binary: OpenVEX
// (documents we export) and the drill report contract.
package schemas

import _ "embed"

// OpenVEX is the pinned OpenVEX 0.2 schema. validate uses these bytes when
// no schema path is given, so the command works outside the repository.
//
//go:embed openvex.schema.json
var OpenVEX []byte

// Report is the JSON Schema (Draft 2020-12) for the drill report.
// `verdict report validate` uses these bytes.
//
//go:embed report.schema.json
var Report []byte
