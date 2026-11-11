// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func hostOpt() HostOptions {
	return HostOptions{AssetID: "lab-host-01", KBVersion: "demo-2026.11.08", Evaluation: "2026-11-08T12:00:00Z"}
}

func hostDocJSON(packages, unparsed, facts, listening string) []byte {
	s := `{"schema":"verdict.collect-host/v1","collector":"collect-host.sh","hostname":"lab-host",` +
		`"collected_at":"2026-11-08T11:00:00Z","os":{"id":"ubuntu","version_id":"22.04"},` +
		`"packages":[` + packages + `],"unparsed":[` + unparsed + `],"facts":{` + facts + `}`
	if listening != "" {
		s += `,"listening":[` + listening + `]`
	}
	return []byte(s + `,"notes":[]}`)
}

const debSSH = `{"manager":"dpkg","name":"openssh-server","version":"1:8.9p1-3ubuntu0.18","purl":"pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.18?distro=ubuntu-22.04&arch=arm64"}`

func factByKey(a snapshot.Asset, key string) (snapshot.Fact, bool) {
	for _, f := range a.Facts {
		if f.Key == key {
			return f, true
		}
	}
	return snapshot.Fact{}, false
}

func TestHostDebEpochAndObservedFacts(t *testing.T) {
	got, err := Host(hostDocJSON(debSSH, "", `"libc.family":"glibc","process.listening.sshd":"true"`, ""), hostOpt())
	if err != nil {
		t.Fatal(err)
	}
	a := got.Snapshot.Assets[0]
	if a.Name != "lab-host" {
		t.Fatalf("asset name should default to hostname: %q", a.Name)
	}
	pkg := a.Inventory.Packages[0]
	if pkg.PURL != "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.18?arch=arm64&distro=ubuntu-22.04" || pkg.Version != "1:8.9p1-3ubuntu0.18" {
		t.Fatalf("epoch must survive canonicalization: %+v", pkg)
	}
	if a.Inventory.Complete {
		t.Fatal("complete must default to false")
	}
	f, ok := factByKey(a, "libc.family")
	if !ok || f.Basis != "observed" || f.Confidence != "high" || f.ObservedAt != "2026-11-08T11:00:00Z" ||
		f.Source != "collect-host.sh" || !strings.HasPrefix(f.EvidenceID, "e-host-") || f.EvidenceID != a.Inventory.EvidenceID {
		t.Fatalf("%+v", f)
	}
}

func TestHostRPMEpochQualifier(t *testing.T) {
	rpm := `{"manager":"rpm","name":"openssh-server","version":"8.7p1-38.el9","purl":"pkg:rpm/rocky/openssh-server@8.7p1-38.el9?epoch=1&arch=x86_64&distro=rocky-9.4"}`
	got, err := Host(hostDocJSON(rpm, "", "", ""), hostOpt())
	if err != nil {
		t.Fatal(err)
	}
	pkg := got.Snapshot.Assets[0].Inventory.Packages[0]
	if pkg.PURL != "pkg:rpm/rocky/openssh-server@8.7p1-38.el9?arch=x86_64&distro=rocky-9.4&epoch=1" || pkg.Version != "8.7p1-38.el9" {
		t.Fatalf("%+v", pkg)
	}
}

func TestHostMissingFactStaysAbsent(t *testing.T) {
	got, err := Host(hostDocJSON(debSSH, "", `"libc.family":"glibc"`, ""), hostOpt())
	if err != nil {
		t.Fatal(err)
	}
	a := got.Snapshot.Assets[0]
	for _, k := range []string{"config.sshd.LoginGraceTime", "process.listening.sshd", "service.socket_activation.sshd"} {
		if _, ok := factByKey(a, k); ok {
			t.Fatalf("%s was not collected and must stay absent", k)
		}
	}
	if len(a.Facts) != 1 {
		t.Fatalf("%+v", a.Facts)
	}
}

func TestHostLoginGraceTimeNormalized(t *testing.T) {
	for in, want := range map[string]string{"0": "0", "120": "120", "2m": "120", "1m30s": "90", "0s": "0"} {
		got, err := Host(hostDocJSON(debSSH, "", `"config.sshd.LoginGraceTime":"`+in+`"`, ""), hostOpt())
		if err != nil {
			t.Fatal(err)
		}
		f, _ := factByKey(got.Snapshot.Assets[0], "config.sshd.LoginGraceTime")
		if f.Value != want {
			t.Fatalf("%s: got %q want %q", in, f.Value, want)
		}
	}
}

func TestHostCompleteRefusedWithUnparsedLine(t *testing.T) {
	o := hostOpt()
	o.Complete = true
	_, err := Host(hostDocJSON(debSSH, `{"manager":"dpkg","line":"install ok installed\tbroken"}`, "", ""), o)
	if err == nil || !strings.Contains(err.Error(), "inventory cannot be complete") {
		t.Fatalf("got %v", err)
	}
	o.Complete = false
	got, err := Host(hostDocJSON(debSSH, `{"manager":"dpkg","line":"broken"}`, "", ""), o)
	if err != nil || len(got.Skipped) != 1 {
		t.Fatalf("incomplete import should skip and continue: %v %+v", err, got)
	}
	o.Complete = true
	got, err = Host(hostDocJSON(debSSH, "", "", ""), o)
	if err != nil || !got.Snapshot.Assets[0].Inventory.Complete {
		t.Fatalf("clean --complete should be honored: %v", err)
	}
}

func TestHostNoExposureWithoutReachableFrom(t *testing.T) {
	doc := hostDocJSON(debSSH, "", `"process.listening.sshd":"true"`, `{"port":22,"proto":"tcp","process":"sshd"}`)
	got, err := Host(doc, hostOpt())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(got.Snapshot.Assets[0].Exposure); n != 0 {
		t.Fatalf("listening alone must not become exposure: %d", n)
	}
	o := hostOpt()
	o.ReachableFrom = []string{"internal"}
	got, err = Host(doc, o)
	if err != nil {
		t.Fatal(err)
	}
	e := got.Snapshot.Assets[0].Exposure
	if len(e) != 1 || e[0].Port != 22 || e[0].Proto != "tcp" || len(e[0].ReachableFrom) != 1 || e[0].ReachableFrom[0] != "internal" {
		t.Fatalf("%+v", e)
	}
	noTable := hostDocJSON(debSSH, "", "", "")
	got, err = Host(noTable, o)
	if err != nil || len(got.Snapshot.Assets[0].Exposure) != 0 || len(got.Notes) == 0 {
		t.Fatalf("unobserved socket table must not become exposure: %v %+v", err, got)
	}
}

func TestHostMalformedInput(t *testing.T) {
	cases := map[string][]byte{
		"not json":        []byte(`{"schema":`),
		"wrong schema":    []byte(`{"schema":"other","collector":"collect-host.sh","collected_at":"2026-11-08T11:00:00Z"}`),
		"bad time":        []byte(`{"schema":"verdict.collect-host/v1","collector":"collect-host.sh","hostname":"h","collected_at":"yesterday","packages":[]}`),
		"unknown field":   []byte(`{"schema":"verdict.collect-host/v1","collector":"collect-host.sh","hostname":"h","collected_at":"2026-11-08T11:00:00Z","env":{"AWS_SECRET":"x"}}`),
		"trailing":        append(hostDocJSON(debSSH, "", "", ""), []byte(` {}`)...),
		"unknown fact":    hostDocJSON(debSSH, "", `"kernel.version":"6.1"`, ""),
		"bad bool":        hostDocJSON(debSSH, "", `"process.listening.sshd":"yes"`, ""),
		"bad libc":        hostDocJSON(debSSH, "", `"libc.family":"bionic"`, ""),
		"bad lgt":         hostDocJSON(debSSH, "", `"config.sshd.LoginGraceTime":"2x"`, ""),
		"bad port":        hostDocJSON(debSSH, "", "", `{"port":0,"proto":"tcp"}`),
		"no packages":     hostDocJSON("", "", "", ""),
		"bad purl":        hostDocJSON(`{"manager":"dpkg","name":"x","version":"1","purl":"deb/x@1"}`, "", "", ""),
		"version differs": hostDocJSON(`{"manager":"dpkg","name":"x","version":"2","purl":"pkg:deb/ubuntu/x@1"}`, "", "", ""),
	}
	for name, doc := range cases {
		if _, err := Host(doc, hostOpt()); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestHostEvidenceIDTracksInput(t *testing.T) {
	a, err := Host(hostDocJSON(debSSH, "", `"libc.family":"glibc"`, ""), hostOpt())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Host(hostDocJSON(debSSH, "", `"libc.family":"musl"`, ""), hostOpt())
	if err != nil {
		t.Fatal(err)
	}
	if a.Snapshot.Assets[0].Inventory.EvidenceID == b.Snapshot.Assets[0].Inventory.EvidenceID {
		t.Fatal("different inputs must not share an evidence id")
	}
}
