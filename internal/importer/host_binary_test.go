// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"strings"
	"testing"
)

func binEntry(version, purl, path string) string {
	return `{"manager":"binary","name":"openssh","version":"` + version + `","purl":"` + purl +
		`","path":"` + path + `","source":"binary_version"}`
}

func TestHostBinaryVersionIsMedium(t *testing.T) {
	doc := hostDocJSON(debSSH+","+binEntry("9.6p1", "pkg:generic/openssh@9.6p1", "/usr/local/sbin/sshd"), "", "", "")
	o := hostOpt()
	o.Complete = true
	got, err := Host(doc, o)
	if err != nil {
		t.Fatal(err)
	}
	inv := got.Snapshot.Assets[0].Inventory
	if inv.Confidence != "high" || !inv.Complete {
		t.Fatalf("inventory quality must be unchanged: %+v", inv)
	}
	var found bool
	for _, p := range inv.Packages {
		switch p.PURL {
		case "pkg:generic/openssh@9.6p1":
			found = true
			if p.Confidence != "medium" || p.Source != HostBinarySource || p.Version != "9.6p1" {
				t.Fatalf("binary entry: %+v", p)
			}
		default:
			if p.Confidence != "" || p.Source != "" {
				t.Fatalf("package-database entry must keep the inventory confidence: %+v", p)
			}
		}
	}
	if !found {
		t.Fatal("binary entry not imported")
	}
	joined := strings.Join(got.Notes, "\n")
	if !strings.Contains(joined, "/usr/local/sbin/sshd banner; confidence medium") {
		t.Fatalf("notes: %q", got.Notes)
	}
}

func TestHostBinaryVersionPlainForm(t *testing.T) {
	got, err := Host(hostDocJSON(binEntry("9.6", "pkg:generic/openssh@9.6", "/usr/sbin/sshd"), "", "", ""), hostOpt())
	if err != nil {
		t.Fatal(err)
	}
	if p := got.Snapshot.Assets[0].Inventory.Packages[0]; p.Version != "9.6" || p.Confidence != "medium" {
		t.Fatalf("%+v", p)
	}
}

func TestHostBinaryOnlyCannotBeComplete(t *testing.T) {
	doc := hostDocJSON(binEntry("9.8p1", "pkg:generic/openssh@9.8p1", "/usr/sbin/sshd"), "", "", "")
	o := hostOpt()
	o.Complete = true
	if _, err := Host(doc, o); err == nil || !strings.Contains(err.Error(), "no package-database entries") {
		t.Fatalf("binary-only --complete must be refused: %v", err)
	}
	if _, err := Host(doc, hostOpt()); err != nil {
		t.Fatalf("binary-only without --complete imports: %v", err)
	}
}

func TestHostBinaryEntryStrict(t *testing.T) {
	ok := binEntry("9.6p1", "pkg:generic/openssh@9.6p1", "/usr/sbin/sshd")
	cases := map[string]string{
		"other name":        strings.Replace(ok, `"name":"openssh"`, `"name":"dropbear"`, 1),
		"purl mismatch":     binEntry("9.6p1", "pkg:generic/openssh@9.8p1", "/usr/sbin/sshd"),
		"purl type":         binEntry("9.6p1", "pkg:deb/openssh@9.6p1", "/usr/sbin/sshd"),
		"distro suffix":     binEntry("9.6p1 Debian-2", "pkg:generic/openssh@9.6p1%20Debian-2", "/usr/sbin/sshd"),
		"letters":           binEntry("9.6p1a", "pkg:generic/openssh@9.6p1a", "/usr/sbin/sshd"),
		"long":              binEntry("9999.6p1", "pkg:generic/openssh@9999.6p1", "/usr/sbin/sshd"),
		"relative path":     binEntry("9.6p1", "pkg:generic/openssh@9.6p1", "sshd"),
		"empty path":        binEntry("9.6p1", "pkg:generic/openssh@9.6p1", ""),
		"newline path":      binEntry("9.6p1", "pkg:generic/openssh@9.6p1", `/usr/sbin/sshd\n`),
		"no source":         strings.Replace(ok, `,"source":"binary_version"`, ``, 1),
		"other source":      strings.Replace(ok, `"binary_version"`, `"banner"`, 1),
		"dpkg with source":  strings.Replace(ok, `"manager":"binary"`, `"manager":"dpkg"`, 1),
		"dpkg with path":    strings.Replace(debSSH, `"manager":"dpkg"`, `"manager":"dpkg","path":"/usr/sbin/sshd"`, 1),
		"unknown field":     strings.Replace(ok, `"source"`, `"confidence":"high","source"`, 1),
		"binary no purl":    strings.Replace(ok, `"purl":"pkg:generic/openssh@9.6p1"`, `"purl":""`, 1),
		"binary empty name": strings.Replace(ok, `"name":"openssh"`, `"name":""`, 1),
	}
	for name, entry := range cases {
		if _, err := Host(hostDocJSON(entry, "", "", ""), hostOpt()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
