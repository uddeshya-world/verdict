// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package reportschema

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/engine"
	"github.com/uddeshya-world/verdict/internal/rootpath"
	"github.com/uddeshya-world/verdict/schemas"
)

func goldens(t *testing.T) []string {
	t.Helper()
	root, err := rootpath.Find()
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, "testdata", "golden", "*-report.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden reports: %v", err)
	}
	return files
}

func TestGoldenReportsValidate(t *testing.T) {
	for _, f := range goldens(t) {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := Validate(data); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
	}
}

func mutate(t *testing.T, data []byte, fn func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestValidateRejects(t *testing.T) {
	data, err := os.ReadFile(goldens(t)[0])
	if err != nil {
		t.Fatal(err)
	}
	first := func(m map[string]any) map[string]any {
		return m["verdicts"].([]any)[0].(map[string]any)
	}
	cases := map[string]func(m map[string]any){
		"unknown top field": func(m map[string]any) { m["extra"] = 1 },
		"missing summary":   func(m map[string]any) { delete(m, "summary") },
		"bad state":         func(m map[string]any) { first(m)["state"] = "safe" },
		"not_affected no just": func(m map[string]any) {
			v := first(m)
			v["state"], v["vex_status"] = "not_affected", "not_affected"
			delete(v, "justification")
		},
		"state vex mismatch": func(m map[string]any) {
			v := first(m)
			v["state"], v["vex_status"] = "exploitable", "not_affected"
		},
		"reason not in catalog": func(m map[string]any) { first(m)["reasons"] = []any{"made_up_reason"} },
		"bad confidence":        func(m map[string]any) { first(m)["confidence"] = "certain" },
		"unknown verdict field": func(m map[string]any) { first(m)["safe"] = true },
	}
	for name, fn := range cases {
		if err := Validate(mutate(t, data, fn)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := Validate(append(append([]byte{}, data...), data...)); err == nil {
		t.Error("trailing document accepted")
	}
}

// TestSchemaMatchesStructs keeps the schema and engine.Report in step: each
// object's properties are exactly the struct's JSON fields, and its required
// list is exactly the fields without omitempty.
func TestSchemaMatchesStructs(t *testing.T) {
	var s map[string]any
	if err := json.Unmarshal(schemas.Report, &s); err != nil {
		t.Fatal(err)
	}
	defs := s["$defs"].(map[string]any)
	check := func(name string, obj map[string]any, typ reflect.Type) {
		var fields, required []string
		for i := 0; i < typ.NumField(); i++ {
			tag := typ.Field(i).Tag.Get("json")
			parts := strings.Split(tag, ",")
			fields = append(fields, parts[0])
			if !slices.Contains(parts[1:], "omitempty") {
				required = append(required, parts[0])
			}
		}
		var props, req []string
		for k := range obj["properties"].(map[string]any) {
			props = append(props, k)
		}
		for _, r := range obj["required"].([]any) {
			req = append(req, r.(string))
		}
		if obj["additionalProperties"] != false {
			t.Errorf("%s: additionalProperties is not false", name)
		}
		sort.Strings(fields)
		sort.Strings(required)
		sort.Strings(props)
		sort.Strings(req)
		if !slices.Equal(fields, props) {
			t.Errorf("%s: schema properties %v, struct fields %v", name, props, fields)
		}
		if !slices.Equal(required, req) {
			t.Errorf("%s: schema required %v, struct non-omitempty %v", name, req, required)
		}
	}
	check("report", s, reflect.TypeOf(engine.Report{}))
	check("summary", defs["summary"].(map[string]any), reflect.TypeOf(engine.Summary{}))
	check("verdict", defs["verdict"].(map[string]any), reflect.TypeOf(engine.Verdict{}))
	check("hint", defs["hint"].(map[string]any), reflect.TypeOf(engine.Hint{}))
	check("proof", defs["proof"].(map[string]any), reflect.TypeOf(engine.ProofView{}))
	check("leaf", defs["leaf"].(map[string]any), reflect.TypeOf(engine.LeafView{}))

	// Every catalog code matches the schema's reason pattern.
	pat := regexp.MustCompile(defs["reason"].(map[string]any)["pattern"].(string))
	for code := range engine.Reasons {
		if !pat.MatchString(code) {
			t.Errorf("catalog code %q does not match the schema reason pattern", code)
		}
	}
}
