// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package snapshot

import (
	"encoding/json"
	"strings"
	"testing"
)

const editBase = `{"kb_version":"kb","evaluation_time":"2026-11-08T12:00:00Z","evidence_trust":"caller_asserted","assets":[
{"id":"a1","name":"a1","kind":"host","zones":[],"inventory":{"complete":false,"observed_at":"2026-11-08T11:00:00Z","basis":"observed","confidence":"high","evidence_id":"e1",
"packages":[{"purl":"pkg:deb/ubuntu/openssh-server@1:8.9p1-3?distro=ubuntu-22.04","version":"1:8.9p1-3"}]},
"facts":[{"key":"libc.family","value":"glibc","basis":"attested","confidence":"medium","observed_at":"2026-11-08T11:00:00Z","evidence_id":"x1","source":"s"}],
"exposure":[{"port":22,"proto":"tcp","reachable_from":["dmz","internal"],"basis":"attested","confidence":"medium","observed_at":"2026-11-08T11:00:00Z","evidence_id":"x2","source":"s"}]},
{"id":"a2","name":"a2","kind":"host","zones":[],"inventory":{"complete":true,"observed_at":"2026-11-08T11:00:00Z","basis":"observed","confidence":"high","evidence_id":"e2","packages":[]},"facts":[],"exposure":[]}]}`

func base(t *testing.T) *Snapshot {
	t.Helper()
	s, err := Load([]byte(editBase))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const ev = EvidenceIDPrefix + "0123456789abcdef"

func wantErr(t *testing.T, edits []Edit, sub string) {
	t.Helper()
	s := base(t)
	before, _ := json.Marshal(s)
	got, err := Apply(s, edits, nil, DefaultMaxBytes)
	if err == nil || !strings.Contains(err.Error(), sub) {
		t.Fatalf("want error containing %q, got %v (result %v)", sub, err, got != nil)
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("input snapshot was modified by a refused edit")
	}
}

func fact(m func(*Edit)) []Edit {
	e := Edit{Op: OpSetFact, Asset: "a2", Key: "k.x", Value: "v"}
	if m != nil {
		m(&e)
	}
	return []Edit{e}
}

func TestEditDefaultsAttestedMedium(t *testing.T) {
	got, err := Apply(base(t), fact(nil), nil, DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	f := got.Assets[1].Facts[0]
	if f.Basis != "attested" || f.Confidence != "medium" || f.ObservedAt != "2026-11-08T12:00:00Z" || f.Source == "" {
		t.Fatalf("%+v", f)
	}
	if got.Assets[1].Inventory.Complete != true || got.Assets[0].Inventory.Complete != false || got.EvidenceTrust != "caller_asserted" {
		t.Fatal("inventory.complete or evidence_trust changed")
	}
}

func TestEditObservedNeedsEvidenceAndTime(t *testing.T) {
	wantErr(t, fact(func(e *Edit) { e.Basis = "observed"; e.ObservedAt = "2026-11-08T11:00:00Z" }), "requires an evidence file")
	wantErr(t, fact(func(e *Edit) { e.Basis = "observed"; e.EvidenceID = ev; e.HasEvidence = true }), "requires observed_at")
	got, err := Apply(base(t), fact(func(e *Edit) {
		e.Basis, e.Confidence, e.EvidenceID, e.HasEvidence, e.ObservedAt = "observed", "high", ev, true, "2026-11-08T11:00:00Z"
	}), nil, DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if f := got.Assets[1].Facts[0]; f.EvidenceID != ev || f.Confidence != "high" {
		t.Fatalf("%+v", f)
	}
}

func TestEditHighNeedsObserved(t *testing.T) {
	wantErr(t, fact(func(e *Edit) { e.Confidence = "high" }), "confidence high requires basis observed")
	wantErr(t, fact(func(e *Edit) { e.Confidence = "confirmed" }), "confidence must be")
	wantErr(t, fact(func(e *Edit) { e.Basis = "inferred" }), "basis must be")
}

func TestEditTimes(t *testing.T) {
	wantErr(t, fact(func(e *Edit) { e.ObservedAt = "2026-11-09T00:00:00Z" }), "after the snapshot evaluation_time")
	wantErr(t, fact(func(e *Edit) { e.ObservedAt = "yesterday" }), "observed_at")
	wantErr(t, fact(func(e *Edit) { e.ObservedAt = "2026-11-08T11:00:00Z"; e.ExpiresAt = "2026-11-08T10:00:00Z" }), "expires_at must be after")
}

func TestEditNoSilentOverwrite(t *testing.T) {
	over := func(e *Edit) { e.Asset, e.Key, e.Value = "a1", "libc.family", "musl" }
	wantErr(t, fact(over), "pass replace")
	got, err := Apply(base(t), fact(func(e *Edit) { over(e); e.Replace = true }), nil, DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Assets[0].Facts) != 1 || got.Assets[0].Facts[0].Value != "musl" {
		t.Fatalf("%+v", got.Assets[0].Facts)
	}
}

func TestEditAssetKeyValue(t *testing.T) {
	wantErr(t, fact(func(e *Edit) { e.Asset = "nope" }), "not in the snapshot")
	wantErr(t, fact(func(e *Edit) { e.Key = "bad key" }), "invalid")
	wantErr(t, fact(func(e *Edit) { e.Key = "" }), "invalid")
	wantErr(t, fact(func(e *Edit) { e.Value = "" }), "value")
	wantErr(t, fact(func(e *Edit) { e.Value = "a\nb" }), "value")
	wantErr(t, fact(func(e *Edit) { e.Source = "a\nb" }), "source")
	// Known collector keys get the collector's value check.
	chk := func(k, v string) (bool, error) {
		if k == "libc.family" && v != "glibc" && v != "musl" {
			return true, errBad
		}
		return k == "libc.family", nil
	}
	_, err := Apply(base(t), fact(func(e *Edit) { e.Key, e.Value = "libc.family", "uclibc" }), chk, DefaultMaxBytes)
	if err == nil {
		t.Fatal("bad value for a known key accepted")
	}
}

type badErr struct{}

func (badErr) Error() string { return "bad value" }

var errBad error = badErr{}

func TestEditPURL(t *testing.T) {
	// Canonically equal spelling (qualifier escape) of the inventory purl is accepted
	// and stored as the inventory's own spelling.
	ok := "pkg:deb/ubuntu/openssh-server@1%3A8.9p1-3?distro=ubuntu-22.04"
	got, err := Apply(base(t), fact(func(e *Edit) { e.Asset, e.PURL = "a1", ok }), nil, DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	last := got.Assets[0].Facts[len(got.Assets[0].Facts)-1]
	if last.PURL != "pkg:deb/ubuntu/openssh-server@1:8.9p1-3?distro=ubuntu-22.04" {
		t.Fatalf("purl %q", last.PURL)
	}
	wantErr(t, fact(func(e *Edit) { e.Asset, e.PURL = "a1", "pkg:deb/ubuntu/curl@1" }), "not an inventory package")
	wantErr(t, fact(func(e *Edit) { e.Asset, e.PURL = "a1", "not-a-purl" }), "purl")
	wantErr(t, fact(func(e *Edit) { e.PURL = ok }), "not an inventory package") // a2 has none
}

func exp(m func(*Edit)) []Edit {
	e := Edit{Op: OpSetExposure, Asset: "a2", Port: 443, Proto: "tcp", ReachableFrom: []string{"internet"}}
	if m != nil {
		m(&e)
	}
	return []Edit{e}
}

func TestEditExposure(t *testing.T) {
	got, err := Apply(base(t), exp(nil), nil, DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if x := got.Assets[1].Exposure[0]; x.Basis != "attested" || x.Confidence != "medium" || x.Port != 443 {
		t.Fatalf("%+v", x)
	}
	wantErr(t, exp(func(e *Edit) { e.Port = 0 }), "port")
	wantErr(t, exp(func(e *Edit) { e.Proto = "icmp" }), "proto")
	wantErr(t, exp(func(e *Edit) { e.ReachableFrom = nil }), "at least one")
	wantErr(t, exp(func(e *Edit) { e.Basis = "observed" }), "evidence file")
	wantErr(t, exp(func(e *Edit) { e.Confidence = "high" }), "requires basis observed")
	wantErr(t, exp(func(e *Edit) { e.Asset = "zz" }), "not in the snapshot")
}

func TestEditExposureWidenNarrow(t *testing.T) {
	at22 := func(z ...string) func(*Edit) {
		return func(e *Edit) { e.Asset, e.Port, e.ReachableFrom = "a1", 22, z }
	}
	// Narrowing (drops internal) and replacing with a disjoint set are refused.
	wantErr(t, exp(at22("dmz")), "would drop")
	wantErr(t, exp(at22("internet")), "would drop")
	// Widening is allowed and yields one entry with the union.
	got, err := Apply(base(t), exp(at22("dmz", "internal", "internet")), nil, DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(got.Assets[0].Exposure); n != 1 || len(got.Assets[0].Exposure[0].ReachableFrom) != 3 {
		t.Fatalf("%+v", got.Assets[0].Exposure)
	}
	// --replace narrows.
	got, err = Apply(base(t), exp(func(e *Edit) { at22("dmz")(e); e.Replace = true }), nil, DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if z := got.Assets[0].Exposure[0].ReachableFrom; len(z) != 1 || z[0] != "dmz" {
		t.Fatalf("%v", z)
	}
	// Another port on the same asset is an add.
	if _, err := Apply(base(t), exp(func(e *Edit) { e.Asset, e.Port = "a1", 2222 }), nil, DefaultMaxBytes); err != nil {
		t.Fatal(err)
	}
}

func TestEditBatchAtomic(t *testing.T) {
	s := base(t)
	before, _ := json.Marshal(s)
	edits := append(fact(nil), Edit{Op: OpSetFact, Asset: "a1", Key: "libc.family", Value: "musl"}) // second needs replace
	if _, err := Apply(s, edits, nil, DefaultMaxBytes); err == nil || !strings.Contains(err.Error(), "edit 2:") {
		t.Fatalf("err = %v", err)
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("input modified")
	}
	if _, err := Apply(s, nil, nil, DefaultMaxBytes); err == nil {
		t.Fatal("empty batch accepted")
	}
	if _, err := Apply(s, []Edit{{Op: "drop"}}, nil, DefaultMaxBytes); err == nil {
		t.Fatal("unknown op accepted")
	}
}

func TestEditSizeCap(t *testing.T) {
	if _, err := Apply(base(t), fact(nil), nil, 100); err == nil {
		t.Fatal("over-cap result accepted")
	}
}

func TestEditPURLScopedFactNeedsReplace(t *testing.T) {
	p := "pkg:deb/ubuntu/openssh-server@1:8.9p1-3?distro=ubuntu-22.04"
	add := func(m func(*Edit)) []Edit {
		e := Edit{Op: OpSetFact, Asset: "a1", Key: "advisory.x", Value: "fixed", PURL: p}
		if m != nil {
			m(&e)
		}
		return []Edit{e}
	}
	s, err := Apply(base(t), add(nil), nil, DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(s, add(func(e *Edit) { e.PURL = "pkg:deb/ubuntu/openssh-server@1%3A8.9p1-3?distro=ubuntu-22.04" }), nil, DefaultMaxBytes); err == nil || !strings.Contains(err.Error(), "pass replace") {
		t.Fatalf("respelled purl overwrote silently: %v", err)
	}
	// The same key without a purl is a different fact.
	if _, err := Apply(s, add(func(e *Edit) { e.PURL = "" }), nil, DefaultMaxBytes); err != nil {
		t.Fatal(err)
	}
}

func TestEditRecordsAppended(t *testing.T) {
	// Non-replace add on a2, then a replace of a1's libc.family, then an
	// exposure add and a narrowing replace.
	edits := []Edit{
		{Op: OpSetFact, Asset: "a2", Key: "k.x", Value: "v", Source: "ticket 1"},
		{Op: OpSetFact, Asset: "a1", Key: "libc.family", Value: "musl", Replace: true, Basis: "observed",
			Confidence: "high", EvidenceID: ev, HasEvidence: true, ObservedAt: "2026-11-08T11:00:00Z"},
		{Op: OpSetExposure, Asset: "a2", Port: 22, Proto: "tcp", ReachableFrom: []string{"dmz"}},
		{Op: OpSetExposure, Asset: "a1", Port: 22, Proto: "tcp", ReachableFrom: []string{"dmz"}, Replace: true},
	}
	got, err := Apply(base(t), edits, nil, DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	a1, a2 := got.Assets[0].Edits, got.Assets[1].Edits
	if len(a1) != 2 || len(a2) != 2 {
		t.Fatalf("a1=%+v a2=%+v", a1, a2)
	}
	if r := a2[0]; r.Op != OpSetFact || r.Replaced || r.NewValue != "v" || r.NewBasis != "attested" || r.At != "2026-11-08T12:00:00Z" || r.Source != "ticket 1" || r.OldValue != "" {
		t.Fatalf("add record: %+v", r)
	}
	if r := a1[0]; !r.Replaced || r.OldValue != "glibc" || r.OldBasis != "attested" || r.NewValue != "musl" || r.NewBasis != "observed" ||
		r.EvidenceID != ev || r.At != "2026-11-08T11:00:00Z" || r.Source == "" {
		t.Fatalf("replace record: %+v", r)
	}
	if r := a2[1]; r.Op != OpSetExposure || r.Replaced || len(r.OldZones) != 0 || len(r.NewZones) != 1 {
		t.Fatalf("exposure add record: %+v", r)
	}
	if r := a1[1]; !r.Replaced || len(r.OldZones) != 2 || len(r.NewZones) != 1 || r.NewZones[0] != "dmz" || r.OldBasis != "attested" {
		t.Fatalf("exposure replace record: %+v", r)
	}
	// Widening an existing port with replace unset is an edit, not a replacement.
	w, err := Apply(base(t), []Edit{{Op: OpSetExposure, Asset: "a1", Port: 22, Proto: "tcp", ReachableFrom: []string{"dmz", "internal", "vpn"}}}, nil, DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if r := w.Assets[0].Edits[0]; r.Replaced || len(r.OldZones) != 2 {
		t.Fatalf("widen record: %+v", r)
	}
	// replace flag with nothing to overwrite records replaced=false.
	n, err := Apply(base(t), fact(func(e *Edit) { e.Replace = true }), nil, DefaultMaxBytes)
	if err != nil || n.Assets[1].Edits[0].Replaced {
		t.Fatalf("%v %+v", err, n.Assets[1].Edits)
	}
}

func TestEditBatchAtomicIncludesEdits(t *testing.T) {
	s := base(t)
	edits := append(fact(nil), Edit{Op: OpSetFact, Asset: "a1", Key: "libc.family", Value: "musl"}) // second needs replace
	if _, err := Apply(s, edits, nil, DefaultMaxBytes); err == nil {
		t.Fatal("batch accepted")
	}
	for _, a := range s.Assets {
		if len(a.Edits) != 0 || len(a.Facts) > 1 {
			t.Fatalf("refused batch left state: %+v", a)
		}
	}
	// A good batch of two edits on one asset records both in order.
	got, err := Apply(s, []Edit{
		{Op: OpSetFact, Asset: "a2", Key: "k.a", Value: "1"},
		{Op: OpSetFact, Asset: "a2", Key: "k.b", Value: "2"},
	}, nil, DefaultMaxBytes)
	if err != nil || len(got.Assets[1].Edits) != 2 || got.Assets[1].Edits[1].Key != "k.b" {
		t.Fatalf("%v %+v", err, got)
	}
	if len(s.Assets[1].Edits) != 0 {
		t.Fatal("input modified")
	}
}

func TestMergeKeepsEdits(t *testing.T) {
	a, err := Apply(snap("a"), []Edit{{Op: OpSetFact, Asset: "a", Key: "k.x", Value: "v"}}, nil, DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Merge(a, snap("b"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Assets[0].Edits) != 1 || m.Assets[0].Edits[0].Key != "k.x" || len(m.Assets[1].Edits) != 0 {
		t.Fatalf("%+v", m.Assets)
	}
}

func TestLoadRejectsMalformedEdits(t *testing.T) {
	good := `{"op":"set_fact","key":"k.x","new_value":"v","new_basis":"attested","replaced":false,"at":"2026-11-08T12:00:00Z","source":"s"}`
	load := func(rec string) error {
		doc := strings.Replace(editBase, `"exposure":[]}]}`, `"exposure":[],"edits":[`+rec+`]}]}`, 1)
		_, err := Load([]byte(doc))
		return err
	}
	if err := load(good); err != nil {
		t.Fatalf("good record rejected: %v", err)
	}
	bad := map[string]string{
		"unknown field":          strings.Replace(good, `"op"`, `"extra":1,"op"`, 1),
		"bad op":                 strings.Replace(good, `"set_fact"`, `"drop"`, 1),
		"no new_basis":           strings.Replace(good, `"new_basis":"attested",`, ``, 1),
		"bad basis":              strings.Replace(good, `"attested"`, `"verified"`, 1),
		"bad at":                 strings.Replace(good, `2026-11-08T12:00:00Z`, `yesterday`, 1),
		"no source":              strings.Replace(good, `"source":"s"`, `"source":""`, 1),
		"newline src":            strings.Replace(good, `"source":"s"`, `"source":"a\nb"`, 1),
		"bad key":                strings.Replace(good, `"k.x"`, `"k x"`, 1),
		"no value":               strings.Replace(good, `"new_value":"v",`, ``, 1),
		"bad evidence":           strings.Replace(good, `"source"`, `"evidence_id":"a b","source"`, 1),
		"replaced w/o old basis": strings.Replace(good, `"replaced":false`, `"replaced":true`, 1),
		"fact with port":         strings.Replace(good, `"op"`, `"port":22,"op"`, 1),
		"exposure no zones":      `{"op":"set_exposure","port":22,"proto":"tcp","new_basis":"attested","replaced":false,"at":"2026-11-08T12:00:00Z","source":"s"}`,
		"exposure bad port":      `{"op":"set_exposure","port":0,"proto":"tcp","new_zones":["a"],"new_basis":"attested","replaced":false,"at":"2026-11-08T12:00:00Z","source":"s"}`,
		"exposure with key":      `{"op":"set_exposure","key":"k","port":22,"proto":"tcp","new_zones":["a"],"new_basis":"attested","replaced":false,"at":"2026-11-08T12:00:00Z","source":"s"}`,
	}
	for name, rec := range bad {
		if err := load(rec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
