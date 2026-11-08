// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package logic

import (
	"reflect"
	"testing"
)

func leaf(v Value, c Confidence, observed bool, just string) Leaf {
	return Leaf{Value: v, Confidence: c, Observed: observed, Justification: just, EvidenceIDs: []string{"e-" + just}}
}

func ref(id string) Node { return Node{Kind: KindRef, Ref: id} }

func TestAllOfShortCircuitAndUnknown(t *testing.T) {
	tree := Node{Kind: KindAll, Kids: []Node{ref("a"), ref("b")}}
	cases := []struct {
		name   string
		a, b   Leaf
		want   Value
		strict bool
	}{
		{"both true", leaf(True, ConfHigh, true, "j"), leaf(True, ConfHigh, true, "j"), True, false},
		{"one false", leaf(False, ConfHigh, true, "vulnerable_code_not_present"), leaf(Unknown, ConfNone, false, ""), False, true},
		{"false and unknown still false", leaf(Unknown, ConfNone, false, ""), leaf(False, ConfHigh, true, "vulnerable_code_not_present"), False, true},
		{"unknown only", leaf(True, ConfHigh, true, "j"), leaf(Unknown, ConfNone, false, ""), Unknown, false},
		{"low false is not strict", leaf(False, ConfLow, true, "vulnerable_code_not_present"), leaf(True, ConfHigh, true, "j"), False, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(tree, map[string]Leaf{"a": tc.a, "b": tc.b})
			if err != nil {
				t.Fatal(err)
			}
			if got.Value != tc.want {
				t.Fatalf("value %s want %s", got.Value, tc.want)
			}
			if (got.StrictFalse != nil) != tc.strict {
				t.Fatalf("strict %v", got.StrictFalse)
			}
		})
	}
}

func TestAnyOfRequiresEveryBranch(t *testing.T) {
	tree := Node{Kind: KindAny, Kids: []Node{ref("a"), ref("b")}}
	high := leaf(False, ConfHigh, true, "vulnerable_code_not_present")
	got, err := Evaluate(tree, map[string]Leaf{
		"a": high,
		"b": leaf(Unknown, ConfNone, false, ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != Unknown || got.StrictFalse != nil {
		t.Fatalf("false+unknown must stay unknown, got %+v", got)
	}

	got, err = Evaluate(tree, map[string]Leaf{
		"a": high,
		"b": leaf(False, ConfLow, true, "vulnerable_code_not_present"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != False || got.StrictFalse != nil {
		t.Fatalf("low branch blocks strict proof: %+v", got)
	}

	got, err = Evaluate(tree, map[string]Leaf{
		"a": high,
		"b": leaf(False, ConfConfirmed, true, "vulnerable_code_not_present"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.StrictFalse == nil || !got.StrictFalse.Uniform || got.StrictFalse.Confidence != ConfHigh {
		t.Fatalf("uniform disjunction proof: %+v", got.StrictFalse)
	}
	if !reflect.DeepEqual(got.StrictFalse.CheckIDs, []string{"a", "b"}) {
		t.Fatalf("proof checks %v", got.StrictFalse.CheckIDs)
	}
}

func TestMixedJustificationNotUniform(t *testing.T) {
	tree := Node{Kind: KindAny, Kids: []Node{ref("a"), ref("b")}}
	got, err := Evaluate(tree, map[string]Leaf{
		"a": leaf(False, ConfHigh, true, "component_not_present"),
		"b": leaf(False, ConfHigh, true, "vulnerable_code_not_present"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != False || got.StrictFalse == nil || got.StrictFalse.Uniform {
		t.Fatalf("expected non-uniform strict false, got %+v", got.StrictFalse)
	}
}

func TestPolarity(t *testing.T) {
	// not(false) is true and is not a false proof.
	notFalse, err := Evaluate(Node{Kind: KindNot, Kids: []Node{ref("m")}}, map[string]Leaf{
		"m": leaf(False, ConfHigh, true, "inline_mitigations_already_exist"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if notFalse.Value != True || notFalse.StrictFalse != nil {
		t.Fatalf("not(false)=true, got %s strict=%v", notFalse.Value, notFalse.StrictFalse != nil)
	}

	// not(true observed) is a strict false proof using that check's justification.
	notTrue, err := Evaluate(Node{Kind: KindNot, Kids: []Node{ref("m")}}, map[string]Leaf{
		"m": leaf(True, ConfHigh, true, "inline_mitigations_already_exist"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if notTrue.Value != False || notTrue.StrictFalse == nil || !notTrue.StrictFalse.Uniform {
		t.Fatalf("not(true) strict false: %+v", notTrue.StrictFalse)
	}
	if notTrue.StrictFalse.Justifications[0] != "inline_mitigations_already_exist" {
		t.Fatalf("justification %v", notTrue.StrictFalse.Justifications)
	}

	// not(any_of(true, unknown)) uses only the true branch.
	tree := Node{Kind: KindNot, Kids: []Node{{Kind: KindAny, Kids: []Node{ref("a"), ref("b")}}}}
	got, err := Evaluate(tree, map[string]Leaf{
		"a": leaf(True, ConfHigh, true, "inline_mitigations_already_exist"),
		"b": leaf(Unknown, ConfNone, false, ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.StrictFalse == nil || !reflect.DeepEqual(got.StrictFalse.CheckIDs, []string{"a"}) {
		t.Fatalf("unknown disjunct must stay out of the proof: %+v", got.StrictFalse)
	}

	// not(all_of(true, unknown)) is unknown.
	tree = Node{Kind: KindNot, Kids: []Node{{Kind: KindAll, Kids: []Node{ref("a"), ref("b")}}}}
	got, err = Evaluate(tree, map[string]Leaf{
		"a": leaf(True, ConfHigh, true, "inline_mitigations_already_exist"),
		"b": leaf(Unknown, ConfNone, false, ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != Unknown || got.StrictFalse != nil {
		t.Fatalf("not(all_of true, unknown) = %s", got.Value)
	}

	// Double negation restores a strict false leaf.
	tree = Node{Kind: KindNot, Kids: []Node{{Kind: KindNot, Kids: []Node{ref("a")}}}}
	got, err = Evaluate(tree, map[string]Leaf{
		"a": leaf(False, ConfConfirmed, true, "vulnerable_code_not_present"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != False || got.StrictFalse == nil || got.StrictFalse.Confidence != ConfConfirmed {
		t.Fatalf("double negation: %+v", got.StrictFalse)
	}

	// not(all_of(true J1, true J2)) is false and not uniform.
	tree = Node{Kind: KindNot, Kids: []Node{{Kind: KindAll, Kids: []Node{ref("a"), ref("b")}}}}
	got, err = Evaluate(tree, map[string]Leaf{
		"a": leaf(True, ConfHigh, true, "inline_mitigations_already_exist"),
		"b": leaf(True, ConfHigh, true, "vulnerable_code_not_present"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != False || got.StrictFalse == nil || got.StrictFalse.Uniform {
		t.Fatalf("mixed negated conjunction: %+v", got.StrictFalse)
	}
	if !reflect.DeepEqual(got.StrictFalse.CheckIDs, []string{"a", "b"}) {
		t.Fatalf("checks %v", got.StrictFalse.CheckIDs)
	}
}

func TestNotObservedCannotStrict(t *testing.T) {
	got, err := Evaluate(ref("a"), map[string]Leaf{
		"a": leaf(False, ConfConfirmed, false, "vulnerable_code_not_present"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != False || got.StrictFalse != nil {
		t.Fatalf("unobserved false must not be strict: %+v", got)
	}
}

func TestDeterministicRepeat(t *testing.T) {
	tree := Node{Kind: KindAll, Kids: []Node{
		ref("a"),
		{Kind: KindNot, Kids: []Node{{Kind: KindAny, Kids: []Node{ref("b"), ref("c")}}}},
	}}
	leaves := map[string]Leaf{
		"a": leaf(True, ConfHigh, true, "vulnerable_code_not_present"),
		"b": leaf(True, ConfHigh, true, "inline_mitigations_already_exist"),
		"c": leaf(False, ConfLow, true, "inline_mitigations_already_exist"),
	}
	a, err := Evaluate(tree, leaves)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Evaluate(tree, leaves)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("not deterministic\n%+v\n%+v", a, b)
	}
}
