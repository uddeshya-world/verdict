// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// Shapes below are trimmed from syft 1.18.1 and trivy 0.58.1 output for
// ubuntu 22.04/24.04, rockylinux 9.3, and alpine 3.20.

func TestCycloneDXIgnoresOperatingSystemComponent(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","components":[
	  {"type":"library","name":"shadow-utils","version":"2:4.9-8.el9","purl":"pkg:rpm/rocky/shadow-utils@4.9-8.el9?arch=aarch64&distro=rocky-9.3&epoch=2&upstream=shadow-utils-4.9-8.el9.src.rpm"},
	  {"type":"library","name":"openssh-server","version":"9.9p1-13.el9_8.rocky.0.1","purl":"pkg:rpm/rocky/openssh-server@9.9p1-13.el9_8.rocky.0.1?arch=aarch64&distro=rocky-9.3&upstream=openssh-9.9p1-13.el9_8.rocky.0.1.src.rpm"},
	  {"type":"operating-system","name":"rocky","version":"9.3"}
	]}`)
	o := opt()
	o.Complete = true
	got, err := CycloneDX(raw, o)
	if err != nil {
		t.Fatalf("syft OS component and rpm epoch must not block --complete: %v", err)
	}
	inv := got.Snapshot.Assets[0].Inventory
	if !inv.Complete || len(inv.Packages) != 2 || len(got.Skipped) != 0 || len(got.Notes) != 1 {
		t.Fatalf("%+v skipped=%v notes=%v", inv, got.Skipped, got.Notes)
	}
	for _, p := range inv.Packages {
		if strings.Contains(p.PURL, "shadow-utils") && (p.Version != "4.9-8.el9" || !strings.Contains(p.PURL, "epoch=2")) {
			t.Fatalf("epoch package must keep its purl version and qualifier: %+v", p)
		}
	}
}

func TestCycloneDXOperatingSystemOnlyWithoutPURLIsIgnored(t *testing.T) {
	// A non-OS component without a purl is still skipped and still blocks --complete.
	raw := []byte(`{"bomFormat":"CycloneDX","components":[
	  {"type":"library","name":"openssh-server","version":"1:8.9p1-3"},
	  {"type":"library","name":"bash","version":"5.1-6ubuntu1","purl":"pkg:deb/ubuntu/bash@5.1-6ubuntu1"},
	  {"type":"operating-system","name":"ubuntu","version":"22.04"}
	]}`)
	o := opt()
	o.Complete = true
	if _, err := CycloneDX(raw, o); err == nil || !strings.Contains(err.Error(), "openssh-server") {
		t.Fatalf("a library without a purl must still refuse --complete: %v", err)
	}
}

func TestEpochMismatchIsStillSkipped(t *testing.T) {
	cases := []string{
		// field says epoch 2, qualifier says epoch 1
		`{"name":"shadow-utils","version":"2:4.9-8.el9","purl":"pkg:rpm/rocky/shadow-utils@4.9-8.el9?epoch=1"}`,
		// field has an epoch, purl has none
		`{"name":"shadow-utils","version":"2:4.9-8.el9","purl":"pkg:rpm/rocky/shadow-utils@4.9-8.el9"}`,
		// epoch only fixes a missing epoch, not a different release
		`{"name":"shadow-utils","version":"2:4.9-9.el9","purl":"pkg:rpm/rocky/shadow-utils@4.9-8.el9?epoch=2"}`,
		// epoch folding is for rpm and deb only
		`{"name":"x","version":"2:1.0","purl":"pkg:npm/x@1.0?epoch=2"}`,
	}
	for _, c := range cases {
		raw := []byte(`{"bomFormat":"CycloneDX","components":[` + c + `,{"name":"bash","version":"5.1","purl":"pkg:deb/ubuntu/bash@5.1"}]}`)
		got, err := CycloneDX(raw, opt())
		if err != nil || len(got.Skipped) != 1 {
			t.Fatalf("%s: %v %+v", c, err, got)
		}
	}
	got, err := CycloneDX([]byte(`{"bomFormat":"CycloneDX","components":[{"name":"x","version":"0:1.0-1","purl":"pkg:rpm/rocky/x@1.0-1"}]}`), opt())
	if err != nil || len(got.Skipped) != 0 {
		t.Fatalf("a zero epoch is no epoch: %v %+v", err, got)
	}
}

func TestTrivyComposesEpochVersionRelease(t *testing.T) {
	raw := []byte(`{"SchemaVersion":2,"Results":[{"Target":"x","Packages":[
	  {"Name":"acl","Version":"2.4.0","Release":"1.el9_8","Identifier":{"PURL":"pkg:rpm/rocky/acl@2.4.0-1.el9_8?arch=aarch64&distro=rocky-9.3"}},
	  {"Name":"dbus","Version":"1.12.20","Release":"8.el9","Epoch":1,"Identifier":{"PURL":"pkg:rpm/rocky/dbus@1.12.20-8.el9?arch=aarch64&distro=rocky-9.3&epoch=1"}},
	  {"Name":"openssh-server","Version":"8.9p1","Release":"3","Epoch":1,"Identifier":{"PURL":"pkg:deb/ubuntu/openssh-server@8.9p1-3?arch=arm64&distro=ubuntu-22.04&epoch=1"}},
	  {"Name":"adduser","Version":"3.118ubuntu5","Identifier":{"PURL":"pkg:deb/ubuntu/adduser@3.118ubuntu5?arch=all&distro=ubuntu-22.04"}},
	  {"Name":"musl","Version":"1.2.5-r3","Identifier":{"PURL":"pkg:apk/alpine/musl@1.2.5-r3?arch=aarch64&distro=3.20.10"}},
	  {"Name":"bash","Version":"5.1","Release":"6ubuntu1.2","Identifier":{"PURL":"pkg:deb/ubuntu/bash@5.1-6ubuntu1.1?distro=ubuntu-22.04"}}
	]}]}`)
	got, err := Trivy(raw, opt())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(got.Snapshot.Assets[0].Inventory.Packages); n != 5 {
		t.Fatalf("packages=%d skipped=%v", n, got.Skipped)
	}
	if len(got.Skipped) != 1 || !strings.HasPrefix(got.Skipped[0], "bash:") {
		t.Fatalf("a real version disagreement must still skip: %v", got.Skipped)
	}
	if names := SkippedNames(got.Skipped); len(names) != 1 || names[0] != "bash" {
		t.Fatalf("%v", names)
	}
}

func TestTrivyNoUsablePackagesListsNames(t *testing.T) {
	raw := []byte(`{"Results":[{"Packages":[{"Name":"openssh","Version":"9.9p1","Release":"2","Identifier":{"PURL":"pkg:rpm/rocky/openssh@9.9p1-1"}}]}]}`)
	if _, err := Trivy(raw, opt()); err == nil || !strings.Contains(err.Error(), "openssh") {
		t.Fatalf("error must name the skipped package: %v", err)
	}
}

func advDoc(t *testing.T, rows ...string) *AdvisoryDocument {
	t.Helper()
	var b strings.Builder
	b.WriteString(`{"facts":[`)
	for i, r := range rows {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"asset_id":"bastion-01","key":"advisory.cve_2024_6387.status","purl":"` + r + `","basis":"observed","confidence":"high","observed_at":"2026-11-08T11:00:00Z","evidence_id":"e","source":"USN-6859-1",`)
		if strings.Contains(r, "ubuntu0.10") {
			b.WriteString(`"value":"fixed"}`)
		} else {
			b.WriteString(`"value":"affected"}`)
		}
	}
	b.WriteString(`]}`)
	doc, err := ParseAdvisories([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func syftUbuntu(t *testing.T, distro string) *snapshot.Snapshot {
	t.Helper()
	raw := []byte(`{"bomFormat":"CycloneDX","components":[
	  {"name":"openssh-server","version":"1:8.9p1-3ubuntu0.10","purl":"pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10?arch=arm64&distro=` + distro + `&upstream=openssh"},
	  {"name":"openssh-server","version":"1:8.9p1-3ubuntu0.10","purl":"pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10?arch=amd64&distro=` + distro + `&upstream=openssh"},
	  {"name":"openssh-client","version":"8.9p1-3","purl":"pkg:deb/ubuntu/openssh-client@8.9p1-3?arch=arm64&distro=` + distro + `&epoch=1"}
	]}`)
	got, err := CycloneDX(raw, opt())
	if err != nil {
		t.Fatal(err)
	}
	return got.Snapshot
}

func TestAdvisoryWithoutQualifiersMatchesScannerPURL(t *testing.T) {
	snap := syftUbuntu(t, "ubuntu-22.04")
	out, rep, err := ApplyAdvisories(snap, advDoc(t, "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10"), AdvisoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	facts := out.Assets[0].Facts
	if len(facts) != 2 || rep.Facts != 2 {
		t.Fatalf("one fact per matched arch: %+v", facts)
	}
	for _, f := range facts {
		if !strings.Contains(f.PURL, "distro=ubuntu-22.04") || !strings.Contains(f.PURL, "arch=") {
			t.Fatalf("fact must carry the inventory's exact purl: %s", f.PURL)
		}
	}
	// Explicit distro that matches, and arch/upstream that differ, still match.
	if _, _, err := ApplyAdvisories(snap, advDoc(t, "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10?distro=ubuntu-22.04&arch=s390x&upstream=other"), AdvisoryOptions{}); err != nil {
		t.Fatal(err)
	}
	// Epoch in the version matches a package whose epoch is in the qualifier.
	out, _, err = ApplyAdvisories(snap, advDoc(t, "pkg:deb/ubuntu/openssh-client@1:8.9p1-3"), AdvisoryOptions{})
	if err != nil || len(out.Assets[0].Facts) != 1 || !strings.Contains(out.Assets[0].Facts[0].PURL, "epoch=1") {
		t.Fatalf("epoch qualifier: %v %+v", err, out)
	}
}

func TestAdvisoryForAnotherDistroDoesNotApply(t *testing.T) {
	snap := syftUbuntu(t, "ubuntu-24.04")
	_, _, err := ApplyAdvisories(snap, advDoc(t, "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10?distro=ubuntu-22.04"), AdvisoryOptions{})
	if err == nil {
		t.Fatal("a 22.04 advisory must never clear a 24.04 package")
	}
	out, rep, err := ApplyAdvisories(snap, advDoc(t, "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10?distro=ubuntu-22.04"), AdvisoryOptions{AllowUnmatched: true})
	if err != nil || len(out.Assets[0].Facts) != 0 || len(rep.Unmatched) != 1 {
		t.Fatalf("--allow-unmatched must drop, not write: %v %+v", err, out.Assets[0].Facts)
	}
	// A package without a distro qualifier does not satisfy a row that names one.
	bare, err := CycloneDX([]byte(`{"bomFormat":"CycloneDX","components":[{"name":"openssh-server","version":"1:8.9p1-3ubuntu0.10","purl":"pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10"}]}`), opt())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ApplyAdvisories(bare.Snapshot, advDoc(t, "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10?distro=ubuntu-22.04"), AdvisoryOptions{}); err == nil {
		t.Fatal("a distro row must not match a package with unknown distro")
	}
}

func TestAdvisoryIdentityMustMatch(t *testing.T) {
	snap := syftUbuntu(t, "ubuntu-22.04")
	for _, row := range []string{
		"pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.6",  // other version
		"pkg:deb/ubuntu/openssh-server@8.9p1-3ubuntu0.10",   // missing epoch
		"pkg:deb/ubuntu/openssh-server@2:8.9p1-3ubuntu0.10", // other epoch
		"pkg:deb/debian/openssh-server@1:8.9p1-3ubuntu0.10", // other namespace
		"pkg:rpm/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10", // other type
		"pkg:deb/ubuntu/openssh-sftp-server@1:8.9p1-3ubuntu0.10",
		"pkg:deb/ubuntu/openssh-server", // no version
		"pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10?repository_url=x",
		"pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10#sub",
	} {
		if _, _, err := ApplyAdvisories(snap, advDoc(t, row), AdvisoryOptions{}); err == nil {
			t.Fatalf("%s must not match", row)
		}
	}
	if _, _, err := ApplyAdvisories(snap, advDoc(t, "pkg:deb/ubuntu/openssh-client@8.9p1-3?epoch=2"), AdvisoryOptions{}); err == nil {
		t.Fatal("epoch qualifier mismatch must not match")
	}
}

func TestAdvisoryConflictOnOnePackageFails(t *testing.T) {
	snap := syftUbuntu(t, "ubuntu-22.04")
	doc := advDoc(t, "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10", "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10?distro=ubuntu-22.04")
	doc.Facts[1].Value = "affected"
	if _, _, err := ApplyAdvisories(snap, doc, AdvisoryOptions{}); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("conflicting rows on one package must fail: %v", err)
	}
	doc.Facts[1].Value = "fixed"
	out, rep, err := ApplyAdvisories(snap, doc, AdvisoryOptions{})
	if err != nil || len(out.Assets[0].Facts) != 2 || rep.Facts != 2 {
		t.Fatalf("agreeing rows are written once per package: %v %+v", err, out.Assets[0].Facts)
	}
}
