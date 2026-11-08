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
