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
