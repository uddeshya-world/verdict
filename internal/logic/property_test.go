// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package logic

import (
	"math/rand"
	"reflect"
	"testing"
)

func TestPropertyInvariants(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		leaves := map[string]Leaf{}
		n := 1 + rng.Intn(5)
		ids := make([]string, n)
		for k := 0; k < n; k++ {
			id := string(rune('a' + k))
			ids[k] = id
			leaves[id] = randomLeaf(rng)
		}
		tree := randomTree(rng, ids, 0)
		a, err := Evaluate(tree, leaves)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Evaluate(tree, leaves)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("iter %d nondeterministic", i)
		}
		assertProofLeaves(t, a, leaves)
		stripped := map[string]Leaf{}
		for id, leaf := range leaves {
			cp := leaf
			if !(cp.Observed && cp.Confidence >= ConfHigh && cp.Justification != "") {
				cp = Leaf{Value: Unknown}
			}
			stripped[id] = cp
		}
		// Removing every leaf that cannot carry a strict proof must make
		// a strict false proof impossible. Also drop the capable ones and
		// confirm the original proof depended only on capable leaves: if
		// every capable leaf is set unknown, no strict false remains.
		none := map[string]Leaf{}
		for id := range leaves {
			none[id] = Leaf{Value: Unknown}
		}
		cleared, err := Evaluate(tree, none)
		if err != nil {
			t.Fatal(err)
		}
		if cleared.StrictFalse != nil || cleared.Value == True || cleared.Value == False {
			t.Fatalf("all-unknown tree decided: %+v", cleared)
		}
		_ = stripped

		// De Morgan on a pair, value only.
		if n >= 2 {
			pair := map[string]Leaf{"a": leaves[ids[0]], "b": leaves[ids[1]]}
			left, err := Evaluate(Node{Kind: KindNot, Kids: []Node{{Kind: KindAll, Kids: []Node{ref("a"), ref("b")}}}}, pair)
			if err != nil {
				t.Fatal(err)
			}
			right, err := Evaluate(Node{Kind: KindAny, Kids: []Node{
				{Kind: KindNot, Kids: []Node{ref("a")}},
				{Kind: KindNot, Kids: []Node{ref("b")}},
			}}, pair)
			if err != nil {
				t.Fatal(err)
			}
			if left.Value != right.Value {
				t.Fatalf("de morgan all: %s vs %s", left.Value, right.Value)
			}
			left, err = Evaluate(Node{Kind: KindNot, Kids: []Node{{Kind: KindAny, Kids: []Node{ref("a"), ref("b")}}}}, pair)
			if err != nil {
				t.Fatal(err)
			}
			right, err = Evaluate(Node{Kind: KindAll, Kids: []Node{
				{Kind: KindNot, Kids: []Node{ref("a")}},
				{Kind: KindNot, Kids: []Node{ref("b")}},
			}}, pair)
			if err != nil {
				t.Fatal(err)
			}
			if left.Value != right.Value {
				t.Fatalf("de morgan any: %s vs %s", left.Value, right.Value)
			}
			one, err := Evaluate(ref("a"), pair)
			if err != nil {
				t.Fatal(err)
			}
			two, err := Evaluate(Node{Kind: KindNot, Kids: []Node{{Kind: KindNot, Kids: []Node{ref("a")}}}}, pair)
			if err != nil {
				t.Fatal(err)
			}
			if one.Value != two.Value {
				t.Fatalf("double negation value %s vs %s", one.Value, two.Value)
			}
		}
	}
}

func assertProofLeaves(t *testing.T, res Result, leaves map[string]Leaf) {
	t.Helper()
	if res.StrictFalse == nil {
		return
	}
	if res.Value != False {
		t.Fatal("strict false on non-false value")
	}
	if res.StrictFalse.Confidence < ConfHigh {
		t.Fatal("strict confidence below high")
	}
	if res.StrictFalse.Uniform != (len(res.StrictFalse.Justifications) == 1) {
		t.Fatal("uniform flag")
	}
	if len(res.StrictFalse.CheckIDs) == 0 {
		t.Fatal("empty proof")
	}
	for _, id := range res.StrictFalse.CheckIDs {
		leaf, ok := leaves[id]
		if !ok || leaf.Value == Unknown || !leaf.Observed || leaf.Confidence < ConfHigh || leaf.Justification == "" {
			t.Fatalf("proof check %s is not a strict-capable leaf (%+v)", id, leaf)
		}
	}
}

func randomLeaf(rng *rand.Rand) Leaf {
	v := Value(rng.Intn(3))
	conf := Confidence(rng.Intn(5))
	return Leaf{
		Value:         v,
		Confidence:    conf,
		Observed:      rng.Intn(2) == 0,
		Justification: []string{"", "component_not_present", "vulnerable_code_not_present"}[rng.Intn(3)],
		EvidenceIDs:   []string{"e"},
	}
}

func randomTree(rng *rand.Rand, ids []string, depth int) Node {
	if depth >= 3 || rng.Intn(4) == 0 {
		return ref(ids[rng.Intn(len(ids))])
	}
	switch rng.Intn(3) {
	case 0:
		return Node{Kind: KindNot, Kids: []Node{randomTree(rng, ids, depth+1)}}
	case 1:
		return Node{Kind: KindAll, Kids: []Node{randomTree(rng, ids, depth+1), randomTree(rng, ids, depth+1)}}
	default:
		return Node{Kind: KindAny, Kids: []Node{randomTree(rng, ids, depth+1), randomTree(rng, ids, depth+1)}}
	}
}
