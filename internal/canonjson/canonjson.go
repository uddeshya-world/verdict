// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package canonjson marshals values with stable encoding options.
package canonjson

import (
	"bytes"
	"encoding/json"
)

// Marshal encodes v with indentation, a trailing newline, and HTML
// escaping disabled so that URLs and justifications are byte-stable.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
