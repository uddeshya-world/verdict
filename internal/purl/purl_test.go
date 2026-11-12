// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package purl

import "testing"

func TestCanonicalSortsQualifiersAndDecodesVersion(t *testing.T) {
	encoded := "pkg:deb/ubuntu/openssh-server@1%3A8.9p1-3ubuntu0.10?distro=ubuntu-22.04&arch=amd64"
	plain := "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10?arch=amd64&distro=ubuntu-22.04"
	got, err := Canonical(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Fatalf("canonical %s", got)
	}
	if !Same(encoded, plain) {
		t.Fatal("encodings of the same package should match")
	}
	if Same(plain, "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10") {
		t.Fatal("dropping qualifiers must not match")
	}
}

func TestCanonicalDoesNotPromoteEscapesIntoDelimiters(t *testing.T) {
	cases := []string{
		"pkg:generic/openssh@9.8p1%3Fx=1",
		"pkg:maven/org.apache.logging.log4j/log4j-core%40x@2.14.1",
		"pkg:deb/ubuntu/openssh-server@1%3A8.9p1-3ubuntu0.10?distro=ubuntu-22.04&arch=amd64",
	}
	for _, raw := range cases {
		got, err := Canonical(raw)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Canonical(got)
		if err != nil || again != got {
			t.Fatalf("not idempotent: %s -> %s -> %s (%v)", raw, got, again, err)
		}
		if _, err := Parse(got); err != nil {
			t.Fatalf("Parse(Canonical(%s)) = %s: %v", raw, got, err)
		}
	}
	version, err := Canonical("pkg:generic/openssh@9.8p1%3Fx=1")
	if err != nil || version != "pkg:generic/openssh@9.8p1%3Fx%3D1" {
		t.Fatalf("version escape became structure: %s %v", version, err)
	}
	name, err := Canonical("pkg:maven/org.apache.logging.log4j/log4j-core%40x@2.14.1")
	if err != nil || name != "pkg:maven/org.apache.logging.log4j/log4j-core%40x@2.14.1" {
		t.Fatalf("name escape became a version marker: %s %v", name, err)
	}
}

func TestCanonicalLowercasesTypeOnly(t *testing.T) {
	got, err := Canonical("pkg:GENERIC/OpenSSH@9.6p1")
	if err != nil || got != "pkg:generic/OpenSSH@9.6p1" {
		t.Fatalf("canonical %s %v", got, err)
	}
	if !DistroType("DEB") {
		t.Fatal("distro type must be case-insensitive")
	}
	p, _ := Parse("pkg:GENERIC/openssh@9.6p1")
	if !Match("pkg:generic/openssh", p) {
		t.Fatal("type match must be case-insensitive")
	}
}

func TestSameFolded(t *testing.T) {
	a := "pkg:deb/ubuntu/OpenSSH-Server@1:8.9p1-3?arch=amd64&distro=ubuntu-22.04"
	b := "pkg:deb/ubuntu/openssh-server@1%3A8.9p1-3?distro=ubuntu-22.04&arch=amd64"
	if Same(a, b) {
		t.Fatal("case variants are not canonical-equal")
	}
	if !SameFolded(a, b) || !SameFolded("pkg:generic/openssh%20@9.6p1", "pkg:generic/openssh@9.6p1") {
		t.Fatal("case and white-space variants must fold together")
	}
	if SameFolded(b, "pkg:deb/ubuntu/openssh-server@1:8.9p1-4?arch=amd64&distro=ubuntu-22.04") {
		t.Fatal("a different version is a different package")
	}
}

func TestRelated(t *testing.T) {
	cases := []struct {
		pattern, pkg string
		want         bool
	}{
		{"pkg:generic/openssh", "pkg:generic/OpenSSH@9.6p1", true},
		{"pkg:generic/openssh", "pkg:generic/openssh%20@9.6p1", true},
		{"pkg:generic/openssh", "pkg:generic/open-ssh@9.6p1", true},
		{"pkg:generic/openssh", "pkg:generic/openssh-portable@9.6p1", true},
		{"pkg:deb/openssh-server", "pkg:deb/ubuntu/OpenSSH-Server@1:8.9p1-3", true},
		{"pkg:apk/openssh-server", "pkg:apk/alpine/openssh-server-pam@9.6_p1-r0", true},
		{"pkg:generic/openssh", "pkg:pypi/openssh@1.0", true},
		{"pkg:generic/openssh", "pkg:deb/ubuntu/openssh-client@1:8.9p1-3", false},
		{"pkg:generic/xz", "pkg:npm/xz-decompress@1.0.0", false},
		{"pkg:maven/org.apache.logging.log4j/log4j-core", "pkg:maven/org.apache.logging.log4j/log4j-api@2.17.1", false},
		{"pkg:generic/openssh", "pkg:generic/libssh@0.10.6", false},
	}
	for _, c := range cases {
		p, err := Parse(c.pkg)
		if err != nil {
			t.Fatal(err)
		}
		if got := Related(c.pattern, p); got != c.want {
			t.Errorf("Related(%s, %s) = %v, want %v", c.pattern, c.pkg, got, c.want)
		}
	}
}
