// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package openvex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Validate checks doc against the OpenVEX JSON Schema at schemaPath.
// Format annotations are enforced when the library knows the format.
func Validate(schemaPath string, doc []byte) error {
	var raw any
	if err := json.Unmarshal(doc, &raw); err != nil {
		return fmt.Errorf("openvex: %w", err)
	}
	f, err := os.Open(schemaPath)
	if err != nil {
		return fmt.Errorf("openvex: schema: %w", err)
	}
	defer f.Close()
	schDoc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		return fmt.Errorf("openvex: schema: %w", err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	const name = "openvex.schema.json"
	if err := c.AddResource(name, schDoc); err != nil {
		return fmt.Errorf("openvex: schema: %w", err)
	}
	sch, err := c.Compile(name)
	if err != nil {
		return fmt.Errorf("openvex: schema compile: %w", err)
	}
	if err := sch.Validate(raw); err != nil {
		return fmt.Errorf("openvex: document is not valid OpenVEX: %w", err)
	}
	// Re-marshal check: callers pass canonical bytes. Reject a trailing
	// second document by decoding strictly once.
	dec := json.NewDecoder(bytes.NewReader(doc))
	var one any
	if err := dec.Decode(&one); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("openvex: trailing JSON")
	}
	return nil
}
