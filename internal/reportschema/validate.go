// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package reportschema validates a drill report against the embedded report
// JSON Schema and the engine reason catalog.
package reportschema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/uddeshya-world/verdict/internal/engine"
	"github.com/uddeshya-world/verdict/schemas"
)

var (
	once     sync.Once
	compiled *jsonschema.Schema
	compErr  error
)

func schema() (*jsonschema.Schema, error) {
	once.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemas.Report))
		if err != nil {
			compErr = fmt.Errorf("report schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		const name = "report.schema.json"
		if err := c.AddResource(name, doc); err != nil {
			compErr = fmt.Errorf("report schema: %w", err)
			return
		}
		compiled, compErr = c.Compile(name)
	})
	return compiled, compErr
}

// Validate checks one report document: exactly one JSON value, valid against
// the report schema, and every reason code a key of engine.Reasons. The schema
// only checks the shape of a reason code; catalog membership is checked here
// so the code list lives in one place (internal/engine/reasons.go).
func Validate(doc []byte) error {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("report: %w", err)
	}
	if dec.More() {
		return fmt.Errorf("report: trailing JSON after the report")
	}
	sch, err := schema()
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("report: does not match report.schema.json: %w", err)
	}
	var rep engine.Report
	if err := json.Unmarshal(doc, &rep); err != nil {
		return fmt.Errorf("report: %w", err)
	}
	for _, v := range rep.Verdicts {
		var codes []string
		codes = append(codes, v.Reasons...)
		for _, h := range v.Hints {
			codes = append(codes, h.Reason)
		}
		for _, l := range v.Leaves {
			if l.Reason != "" {
				codes = append(codes, l.Reason)
			}
		}
		if v.Proof != nil {
			codes = append(codes, v.Proof.SuppressReasons...)
		}
		for _, c := range codes {
			if _, ok := engine.Reasons[c]; !ok {
				return fmt.Errorf("report: asset %s: reason %q is not in the reason catalog (verdict explain --all)", v.AssetID, c)
			}
		}
	}
	return nil
}
