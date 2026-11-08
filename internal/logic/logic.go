// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package logic evaluates condition trees with Kleene three-valued logic
// and selects a sufficient false proof for not_affected.
// It performs no I/O and does not read the clock.
package logic

import (
	"fmt"
	"sort"
)

// Value is a Kleene truth value.
type Value uint8

const (
	// Unknown means the subtree cannot be decided.
	Unknown Value = iota
	// True means the subtree holds.
	True
	// False means the subtree does not hold.
	False
)

// String returns true, false, or unknown.
func (v Value) String() string {
	switch v {
	case True:
		return "true"
	case False:
		return "false"
	default:
		return "unknown"
	}
}

// Confidence is an ordered caller-asserted confidence.
type Confidence uint8

const (
	// ConfNone means no confidence was established.
	ConfNone Confidence = iota
	// ConfLow is below the not_affected bar.
	ConfLow
	// ConfMedium is below the not_affected bar.
	ConfMedium
	// ConfHigh meets the not_affected bar.
	ConfHigh
	// ConfConfirmed is stronger than high and still caller-asserted.
	ConfConfirmed
)

// ParseConfidence parses a snapshot or pack confidence label.
func ParseConfidence(s string) (Confidence, bool) {
	switch s {
	case "low":
		return ConfLow, true
	case "medium":
		return ConfMedium, true
	case "high":
		return ConfHigh, true
	case "confirmed":
		return ConfConfirmed, true
	default:
		return ConfNone, false
	}
}

// String returns the label, or "none".
func (c Confidence) String() string {
	switch c {
	case ConfLow:
		return "low"
	case ConfMedium:
		return "medium"
	case ConfHigh:
		return "high"
	case ConfConfirmed:
		return "confirmed"
	default:
		return "none"
	}
}

// Min returns the lower confidence.
func Min(a, b Confidence) Confidence {
	if a < b {
		return a
	}
	return b
}

// Leaf is one check result already reduced by the engine.
// Polarity is applied by the tree: a positive leaf falsifies when Value
// is False; a leaf under not falsifies when Value is True.
type Leaf struct {
	Value         Value
	Confidence    Confidence
	Observed      bool
	Justification string
	EvidenceIDs   []string
}

// Kind discriminates a condition node.
type Kind uint8

const (
	// KindRef names a leaf.
	KindRef Kind = iota
	// KindNot negates one child.
	KindNot
	// KindAll is a conjunction.
	KindAll
	// KindAny is a disjunction.
	KindAny
)

// Node is a condition tree.
type Node struct {
	Kind Kind
	Ref  string
	Kids []Node
}

// StrictFalse is a sufficient observed proof that the node is false.
type StrictFalse struct {
	Confidence     Confidence
	Justifications []string
	Uniform        bool
	CheckIDs       []string
	EvidenceIDs    []string
}

// Result is the Kleene value plus the proofs needed to derive a verdict.
type Result struct {
	Value      Value
	TrueConf   Confidence
	TrueChecks []string

	strictTrue       bool
	strictTrueConf   Confidence
	strictTrueChecks []string
	strictTrueJust   []string
	strictTrueEv     []string

	looseFalseConf   Confidence
	looseFalseChecks []string

	// StrictFalse is set only when a sufficient high-confidence observed
	// proof of false exists.
	StrictFalse *StrictFalse
}

// Evaluate walks the tree. Missing refs and empty groups are errors.
func Evaluate(n Node, leaves map[string]Leaf) (Result, error) {
	return eval(n, leaves)
}

func eval(n Node, leaves map[string]Leaf) (Result, error) {
	switch n.Kind {
	case KindRef:
		leaf, ok := leaves[n.Ref]
		if !ok {
			return Result{}, fmt.Errorf("logic: missing leaf %q", n.Ref)
		}
		if n.Ref == "" {
			return Result{}, fmt.Errorf("logic: empty ref")
		}
		return fromLeaf(n.Ref, leaf), nil
	case KindNot:
		if len(n.Kids) != 1 {
			return Result{}, fmt.Errorf("logic: not must have one child")
		}
		c, err := eval(n.Kids[0], leaves)
		if err != nil {
			return Result{}, err
		}
		return negate(c), nil
	case KindAll:
		if len(n.Kids) == 0 {
			return Result{}, fmt.Errorf("logic: empty all_of")
		}
		kids, err := evalKids(n.Kids, leaves)
		if err != nil {
			return Result{}, err
		}
		return allOf(kids), nil
	case KindAny:
		if len(n.Kids) == 0 {
			return Result{}, fmt.Errorf("logic: empty any_of")
		}
		kids, err := evalKids(n.Kids, leaves)
		if err != nil {
			return Result{}, err
		}
		return anyOf(kids), nil
	default:
		return Result{}, fmt.Errorf("logic: unknown node kind %d", n.Kind)
	}
}

func evalKids(nodes []Node, leaves map[string]Leaf) ([]Result, error) {
	out := make([]Result, len(nodes))
	for i, n := range nodes {
		c, err := eval(n, leaves)
		if err != nil {
			return nil, err
		}
		out[i] = c
	}
	return out, nil
}

func fromLeaf(id string, l Leaf) Result {
	ev := uniqSorted(l.EvidenceIDs)
	switch l.Value {
	case True:
		r := Result{Value: True, TrueConf: l.Confidence, TrueChecks: []string{id}}
		if l.Observed && l.Confidence >= ConfHigh && l.Justification != "" {
			r.strictTrue = true
			r.strictTrueConf = l.Confidence
			r.strictTrueChecks = []string{id}
			r.strictTrueJust = []string{l.Justification}
			r.strictTrueEv = ev
		}
		return r
	case False:
		r := Result{Value: False, looseFalseConf: l.Confidence, looseFalseChecks: []string{id}}
		if l.Observed && l.Confidence >= ConfHigh && l.Justification != "" {
			r.StrictFalse = &StrictFalse{
				Confidence:     l.Confidence,
				Justifications: []string{l.Justification},
				Uniform:        true,
				CheckIDs:       []string{id},
				EvidenceIDs:    ev,
			}
		}
		return r
	default:
		return Result{Value: Unknown}
	}
}

func negate(c Result) Result {
	switch c.Value {
	case Unknown:
		return Result{Value: Unknown}
	case True:
		out := Result{
			Value:            False,
			looseFalseConf:   c.TrueConf,
			looseFalseChecks: append([]string{}, c.TrueChecks...),
		}
		if c.strictTrue {
			js := uniqSorted(c.strictTrueJust)
			out.StrictFalse = &StrictFalse{
				Confidence:     c.strictTrueConf,
				Justifications: js,
				Uniform:        len(js) == 1,
				CheckIDs:       uniqSorted(c.strictTrueChecks),
				EvidenceIDs:    uniqSorted(c.strictTrueEv),
			}
		}
		return out
	case False:
		out := Result{
			Value:      True,
			TrueConf:   c.looseFalseConf,
			TrueChecks: append([]string{}, c.looseFalseChecks...),
		}
		if c.StrictFalse != nil {
			out.TrueConf = c.StrictFalse.Confidence
			out.TrueChecks = append([]string{}, c.StrictFalse.CheckIDs...)
			out.strictTrue = true
			out.strictTrueConf = c.StrictFalse.Confidence
			out.strictTrueChecks = append([]string{}, c.StrictFalse.CheckIDs...)
			out.strictTrueJust = append([]string{}, c.StrictFalse.Justifications...)
			out.strictTrueEv = append([]string{}, c.StrictFalse.EvidenceIDs...)
		}
		return out
	default:
		return Result{Value: Unknown}
	}
}

func allOf(kids []Result) Result {
	var loose *Result
	var strict *Result
	trues := make([]Result, 0, len(kids))
	unknown := false
	for i := range kids {
		c := kids[i]
		switch c.Value {
		case False:
			if loose == nil || c.looseFalseConf > loose.looseFalseConf {
				cc := c
				loose = &cc
			}
			if c.StrictFalse != nil && (strict == nil || c.StrictFalse.Confidence > strict.StrictFalse.Confidence) {
				cc := c
				strict = &cc
			}
		case Unknown:
			unknown = true
		case True:
			trues = append(trues, c)
		}
	}
	if loose != nil {
		out := Result{
			Value:            False,
			looseFalseConf:   loose.looseFalseConf,
			looseFalseChecks: append([]string{}, loose.looseFalseChecks...),
		}
		if strict != nil {
			out.StrictFalse = copyStrict(strict.StrictFalse)
		}
		return out
	}
	if unknown {
		return Result{Value: Unknown}
	}
	return combineTrue(trues)
}

func anyOf(kids []Result) Result {
	var bestTrue *Result
	var bestStrict *Result
	falses := make([]Result, 0, len(kids))
	unknown := false
	for i := range kids {
		c := kids[i]
		switch c.Value {
		case True:
			if bestTrue == nil || c.TrueConf > bestTrue.TrueConf {
				cc := c
				bestTrue = &cc
			}
			if c.strictTrue && (bestStrict == nil || c.strictTrueConf > bestStrict.strictTrueConf) {
				cc := c
				bestStrict = &cc
			}
		case False:
			falses = append(falses, c)
		case Unknown:
			unknown = true
		}
	}
	if bestTrue != nil {
		out := Result{
			Value:      True,
			TrueConf:   bestTrue.TrueConf,
			TrueChecks: append([]string{}, bestTrue.TrueChecks...),
		}
		if bestStrict != nil {
			out.strictTrue = true
			out.strictTrueConf = bestStrict.strictTrueConf
			out.strictTrueChecks = append([]string{}, bestStrict.strictTrueChecks...)
			out.strictTrueJust = append([]string{}, bestStrict.strictTrueJust...)
			out.strictTrueEv = append([]string{}, bestStrict.strictTrueEv...)
		}
		return out
	}
	if unknown {
		return Result{Value: Unknown}
	}
	out := Result{Value: False}
	conf := ConfConfirmed
	var checks []string
	for _, f := range falses {
		conf = Min(conf, f.looseFalseConf)
		checks = append(checks, f.looseFalseChecks...)
	}
	out.looseFalseConf = conf
	out.looseFalseChecks = uniqSorted(checks)
	if s := combineStrict(falses); s != nil {
		out.StrictFalse = s
	}
	return out
}

func combineTrue(trues []Result) Result {
	conf := ConfConfirmed
	strict := true
	strictConf := ConfConfirmed
	var checks, schecks, sjust, sev []string
	for _, c := range trues {
		conf = Min(conf, c.TrueConf)
		checks = append(checks, c.TrueChecks...)
		if !c.strictTrue {
			strict = false
			continue
		}
		strictConf = Min(strictConf, c.strictTrueConf)
		schecks = append(schecks, c.strictTrueChecks...)
		sjust = append(sjust, c.strictTrueJust...)
		sev = append(sev, c.strictTrueEv...)
	}
	out := Result{
		Value:      True,
		TrueConf:   conf,
		TrueChecks: uniqSorted(checks),
	}
	if strict {
		out.strictTrue = true
		out.strictTrueConf = strictConf
		out.strictTrueChecks = uniqSorted(schecks)
		out.strictTrueJust = uniqSorted(sjust)
		out.strictTrueEv = uniqSorted(sev)
	}
	return out
}

func combineStrict(parts []Result) *StrictFalse {
	if len(parts) == 0 {
		return nil
	}
	conf := ConfConfirmed
	var js, ids, ev []string
	for _, p := range parts {
		if p.StrictFalse == nil {
			return nil
		}
		conf = Min(conf, p.StrictFalse.Confidence)
		js = append(js, p.StrictFalse.Justifications...)
		ids = append(ids, p.StrictFalse.CheckIDs...)
		ev = append(ev, p.StrictFalse.EvidenceIDs...)
	}
	js = uniqSorted(js)
	return &StrictFalse{
		Confidence:     conf,
		Justifications: js,
		Uniform:        len(js) == 1,
		CheckIDs:       uniqSorted(ids),
		EvidenceIDs:    uniqSorted(ev),
	}
}

func copyStrict(s *StrictFalse) *StrictFalse {
	if s == nil {
		return nil
	}
	return &StrictFalse{
		Confidence:     s.Confidence,
		Justifications: append([]string{}, s.Justifications...),
		Uniform:        s.Uniform,
		CheckIDs:       append([]string{}, s.CheckIDs...),
		EvidenceIDs:    append([]string{}, s.EvidenceIDs...),
	}
}

func uniqSorted(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	cp := append([]string{}, in...)
	sort.Strings(cp)
	out := make([]string, 0, len(cp))
	var prev string
	for i, s := range cp {
		if i == 0 || s != prev {
			out = append(out, s)
			prev = s
		}
	}
	return out
}
