// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package schemas holds the OpenVEX JSON Schema embedded in the binary.
package schemas

import _ "embed"

// OpenVEX is the pinned OpenVEX 0.2 schema. validate uses these bytes when
// no schema path is given, so the command works outside the repository.
//
//go:embed openvex.schema.json
var OpenVEX []byte
