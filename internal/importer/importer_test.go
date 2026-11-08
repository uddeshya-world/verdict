// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"strings"
	"testing"
)

func opt() InventoryOptions {
	return InventoryOptions{
		AssetID: "bastion-01", AssetName: "bastion", KBVersion: "demo-2026.11.08",
		Evaluation: "2026-11-08T12:00:00Z", ObservedAt: "2026-11-08T11:00:00Z",
		EvidenceID: "e-sbom",
	}
}

func TestCycloneDXSkipsUnpurlAndIgnoresExtraFields(t *testing.T) {
	raw := []byte(`{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "vulnerabilities": [{"id": "CVE-2024-6387"}],
	  "components": [
	    {"name": "openssh-server", "version": "1:8.9p1-3ubuntu0.10", "purl": "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10"},
	    {"name": "notes", "version": "1"}
	  ]
	}`)
	got, err := CycloneDX(raw, opt())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Snapshot.Assets) != 1 || len(got.Snapshot.Assets[0].Facts) != 0 {
		t.Fatalf("vulnerability list must not become facts: %+v", got.Snapshot.Assets[0])
	}
	inv := got.Snapshot.Assets[0].Inventory
	if inv.Complete || inv.Basis != "attested" || inv.Confidence != "medium" {
		t.Fatalf("defaults must not be strong enough to clear a finding: %+v", inv)
	}
	if len(inv.Packages) != 1 || inv.Packages[0].PURL != "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10" {
		t.Fatalf("%+v", inv.Packages)
	}
	if len(got.Skipped) != 1 || !strings.Contains(got.Skipped[0], "notes") {
		t.Fatalf("skipped: %v", got.Skipped)
	}
}

func TestTrivyIgnoresVulnerabilityDecisions(t *testing.T) {
	raw := []byte(`{
	  "SchemaVersion": 2,
	  "Results": [{
	    "Target": "ubuntu",
	    "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-6387", "FixedVersion": "1:9.6p1"}],
	    "Packages": [
	      {"Name": "openssh-server", "Version": "1:8.9p1-3ubuntu0.10", "Identifier": {"PURL": "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10"}},
	      {"Name": "bash", "Version": "5.1"}
	    ]
	  }]
	}`)
	got, err := Trivy(raw, opt())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Snapshot.Assets[0].Facts) != 0 || len(got.Snapshot.Assets[0].Inventory.Packages) != 1 {
		t.Fatalf("%+v", got.Snapshot.Assets[0])
	}
	if len(got.Skipped) != 1 {
		t.Fatalf("skipped: %v", got.Skipped)
	}
}

func TestAdvisoryOverlayIsExplicit(t *testing.T) {
	sbom, err := CycloneDX([]byte(`{"bomFormat":"CycloneDX","components":[{"name":"openssh-server","version":"1:8.9p1-3ubuntu0.10","purl":"pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10"}]}`), opt())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseAdvisories([]byte(`{"facts":[{
	  "asset_id": "bastion-01",
	  "key": "advisory.cve_2024_6387.status",
	  "purl": "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10",
	  "value": "not_affected",
	  "basis": "observed",
	  "confidence": "high",
	  "observed_at": "2026-11-08T11:00:00Z",
	  "evidence_id": "e-usn",
	  "source": "local-note"
	}]}`))
	if err != nil {
		t.Fatal(err)
	}
	out, warnings, err := ApplyAdvisories(sbom.Snapshot, doc)
	if err != nil {
		t.Fatal(err)
	}
	f := out.Assets[0].Facts
	if len(f) != 1 || f[0].Value != "not_affected" || f[0].PURL == "" {
		t.Fatalf("%+v", f)
	}
	if len(warnings) != 0 {
		t.Fatalf("matching purl should not warn: %v", warnings)
	}
	doc.Facts[0].PURL = "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.6"
	if _, warnings, err = ApplyAdvisories(sbom.Snapshot, doc); err != nil || len(warnings) != 1 {
		t.Fatalf("unmatched purl warning: %v %v", warnings, err)
	}
	if _, err := ParseAdvisories([]byte(`{"facts":[{"asset_id":"a","key":"k","purl":"pkg:deb/ubuntu/openssh-server@1","value":"patched","basis":"observed","confidence":"high","observed_at":"2026-11-08T11:00:00Z","evidence_id":"e","source":"s"}]}`)); err == nil {
		t.Fatal("patched is not an advisory value")
	}
}

func TestCompleteRejectsSkippedComponents(t *testing.T) {
	good := `{"name":"bash","version":"5.1-6ubuntu1","purl":"pkg:deb/ubuntu/bash@5.1-6ubuntu1"}`
	cases := []string{
		`{"bomFormat":"CycloneDX","components":[{"name":"openssh-server","version":"1:8.9p1-3ubuntu0.6"},` + good + `]}`,
		`{"bomFormat":"CycloneDX","components":[{"name":"openssh-server","version":"1","purl":"not a purl"},` + good + `]}`,
		`{"bomFormat":"CycloneDX","components":[{"name":"openssh-server","version":"1:8.9p1-3ubuntu0.6","purl":"pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10"},` + good + `]}`,
		`{"bomFormat":"CycloneDX","components":[` + good + `,` + good + `]}`,
	}
	o := opt()
	o.Complete = true
	for _, raw := range cases {
		got, err := CycloneDX([]byte(raw), o)
		if err == nil || got != nil || !strings.Contains(err.Error(), "inventory cannot be complete") {
			t.Fatalf("complete import with a skip must fail closed: %v %+v", err, got)
		}
	}
	got, err := CycloneDX([]byte(`{"bomFormat":"CycloneDX","components":[`+good+`]}`), o)
	if err != nil || !got.Snapshot.Assets[0].Inventory.Complete || len(got.Skipped) != 0 {
		t.Fatalf("complete import of a fully identified BOM: %v %+v", err, got)
	}
}
