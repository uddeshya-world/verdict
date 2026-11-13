// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// snakeCase matches the shape of every reason code.
var snakeCase = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)+$`)

// nonReasonLiterals are snake_case strings engine code may use that are not
// reason codes: verdict states, VEX statuses, check types, exposure kinds, and
// the evidence_trust label. Adding a reason here instead of to reasons.go
// defeats the test, so a new entry needs a reviewer's eye.
var nonReasonLiterals = map[string]bool{
	"caller_asserted_unverified": true,
	"file_exists":                true,
	"manual_attestation":         true,
	"needs_review":               true,
	"not_affected":               true,
	"package_version":            true,
	"process_listening":          true,
	"process_running":            true,
	"trusted_only":               true,
	"under_investigation":        true,
	"vulnerable_not_exposed":     true,
}

// TestReasonLiteralsUseCatalog scans the non-test engine sources. Reason codes
// may be spelled out only in reasons.go, as Reason* constants; every other
// snake_case string literal (struct tags excluded) must be on the short
// non-reason allowlist. A new reason written as a bare literal fails here, so
// it cannot reach a report without a catalog entry.
func TestReasonLiteralsUseCatalog(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	consts := map[string]string{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		tags := map[*ast.BasicLit]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			if fld, ok := n.(*ast.Field); ok && fld.Tag != nil {
				tags[fld.Tag] = true
			}
			return true
		})
		if path == "reasons.go" {
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, s := range gd.Specs {
					vs := s.(*ast.ValueSpec)
					for i, name := range vs.Names {
						if !strings.HasPrefix(name.Name, "Reason") || i >= len(vs.Values) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok {
							t.Errorf("reasons.go: %s is not a string literal", name.Name)
							continue
						}
						v, _ := strconv.Unquote(lit.Value)
						consts[name.Name] = v
					}
				}
			}
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || tags[lit] {
				return true
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil || !snakeCase.MatchString(v) {
				return true
			}
			pos := fset.Position(lit.Pos())
			if _, isReason := Reasons[v]; isReason {
				t.Errorf("%s: reason %q written as a literal; use its Reason* constant", pos, v)
			} else if !nonReasonLiterals[v] {
				t.Errorf("%s: snake_case literal %q is neither a catalog reason nor allowlisted; add a Reason* constant and catalog entry", pos, v)
			}
			return true
		})
	}
	if len(consts) == 0 {
		t.Fatal("no Reason* constants found in reasons.go")
	}
	seen := map[string]string{}
	for name, v := range consts {
		if _, ok := Reasons[v]; !ok {
			t.Errorf("constant %s = %q has no catalog entry", name, v)
		}
		if prev, dup := seen[v]; dup {
			t.Errorf("constants %s and %s share value %q", prev, name, v)
		}
		seen[v] = name
	}
	for code := range Reasons {
		if _, ok := seen[code]; !ok {
			t.Errorf("catalog entry %q has no Reason* constant", code)
		}
	}
}

var placeholder = regexp.MustCompile(`\{[a-z_]+\}`)

func TestReasonCatalogEntries(t *testing.T) {
	if len(Reasons) == 0 {
		t.Fatal("empty catalog")
	}
	for code, info := range Reasons {
		if !snakeCase.MatchString(code) {
			t.Errorf("%s: code is not snake_case", code)
		}
		if strings.TrimSpace(info.Hint) == "" || strings.TrimSpace(info.NextAction) == "" {
			t.Errorf("%s: empty hint or next_action", code)
		}
		if !slices.Contains(ValidKinds, info.Kind) {
			t.Errorf("%s: kind %q", code, info.Kind)
		}
		if !slices.Contains(ValidActors, info.Actor) {
			t.Errorf("%s: actor %q", code, info.Actor)
		}
		for _, p := range placeholder.FindAllString(info.Hint, -1) {
			if p != "{check}" && p != "{detail}" && p != "{detail_q}" {
				t.Errorf("%s: unknown placeholder %s", code, p)
			}
			if info.Kind != KindLeaf {
				t.Errorf("%s: %s kind hint has placeholder %s, but decision hints are not rendered", code, info.Kind, p)
			}
		}
		if placeholder.MatchString(info.DecisionHint) || placeholder.MatchString(info.NextAction) {
			t.Errorf("%s: placeholder outside a leaf hint", code)
		}
		// next_action must not tell anyone to assert the missing evidence.
		lower := strings.ToLower(info.NextAction)
		for _, bad := range []string{"set status reviewed", "set confidence", "mark observed"} {
			if strings.Contains(lower, bad) {
				t.Errorf("%s: next_action contains %q", code, bad)
			}
		}
	}
}

func TestHintsComeFromCatalog(t *testing.T) {
	for code, info := range Reasons {
		if info.Kind == KindLeaf {
			got := leafHint(code, "C9", "fact.key", "")
			if strings.Contains(got, "is unresolved ("+code+")") {
				t.Errorf("%s: leaf hint fell back to generic text", code)
			}
			if strings.Contains(got, "{") {
				t.Errorf("%s: unrendered placeholder: %s", code, got)
			}
			continue
		}
		if code == ReasonEvaluationError {
			continue
		}
		if decisionHint(code) == code {
			t.Errorf("%s: decision hint is the bare code", code)
		}
	}
	// zone_policy_missing is emitted as a decision reason; it used to print bare.
	if decisionHint(ReasonZonePolicyMissing) != Reasons[ReasonZonePolicyMissing].Hint {
		t.Fatal("zone_policy_missing decision hint is not the catalog text")
	}
	if got := leafHint(ReasonMissingFact, "C1", `a"b`, "do X"); !strings.Contains(got, `fact "a\"b"`) || !strings.HasSuffix(got, " Pack hint: do X") {
		t.Fatalf("render: %s", got)
	}
	// A placeholder inside a value is not re-expanded.
	if got := leafHint(ReasonConflictingAdvisory, "{detail}", "D", ""); !strings.HasPrefix(got, "Check {detail} found") {
		t.Fatalf("re-expanded: %s", got)
	}
}
