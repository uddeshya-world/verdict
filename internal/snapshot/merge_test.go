// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package snapshot

import "testing"

func snap(id string) *Snapshot {
	s, err := Load([]byte(`{
	  "kb_version": "demo-2026.11.08",
	  "evaluation_time": "2026-11-08T12:00:00Z",
	  "evidence_trust": "caller_asserted",
	  "assets": [{
	    "id": "` + id + `",
	    "name": "` + id + `",
	    "kind": "host",
	    "zones": [],
	    "inventory": {
	      "complete": false,
	      "observed_at": "2026-11-08T11:00:00Z",
	      "basis": "attested",
	      "confidence": "medium",
	      "evidence_id": "e-` + id + `",
	      "packages": [{"purl": "pkg:deb/ubuntu/bash@5.1-6ubuntu1", "version": "5.1-6ubuntu1"}]
	    },
	    "facts": [],
	    "exposure": []
	  }]
	}`))
	if err != nil {
		panic(err)
	}
	return s
}

func TestMergeRejectsDuplicateAssets(t *testing.T) {
	got, err := Merge(snap("a"), snap("b"))
	if err != nil || len(got.Assets) != 2 {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := Merge(snap("a"), snap("a")); err == nil {
		t.Fatal("duplicate asset must fail")
	}
	other := snap("c")
	other.KBVersion = "other"
	if _, err := Merge(snap("a"), other); err == nil {
		t.Fatal("different kb version must fail")
	}
}
