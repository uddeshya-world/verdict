// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package vercmp

import "testing"

func TestOpenSSHRanges(t *testing.T) {
	ranges := []string{">=8.5p1 <9.8p1", "<4.4p1"}
	in := func(v string) bool {
		for _, r := range ranges {
			ok, err := InRange(SchemeOpenSSH, v, r)
			if err != nil {
				t.Fatalf("%s %s: %v", v, r, err)
			}
			if ok {
				return true
			}
		}
		return false
	}
	if !in("8.5p1") || !in("9.7p1") || !in("9.6p1") || !in("4.3p1") {
		t.Fatal("expected vulnerable upstream versions")
	}
	if in("9.8p1") || in("4.4p1") || in("8.4p1") {
		t.Fatal("expected versions outside the Qualys ranges")
	}
	for _, bad := range []string{"1:8.9p1-3ubuntu0.10", "8.9p1-3ubuntu0.10", "9.8p1ubuntu1", "9.8", "v9.8p1"} {
		if _, err := InRange(SchemeOpenSSH, bad, ">=8.5p1 <9.8p1"); err == nil {
			t.Fatalf("expected parse failure for %s", bad)
		}
	}
}

func TestMavenLog4jRanges(t *testing.T) {
	ranges := []string{">=2.0-beta9 <2.3.1", ">=2.4 <2.12.2", ">=2.13.0 <2.15.0"}
	in := func(v string) (bool, error) {
		var saw bool
		for _, r := range ranges {
			ok, err := InRange(SchemeMaven, v, r)
			if err != nil {
				return false, err
			}
			saw = saw || ok
		}
		return saw, nil
	}
	yes := []string{"2.0-beta9", "2.3.0", "2.4", "2.9.1", "2.12.1", "2.14.1", "2.13.0"}
	no := []string{"2.0-beta8", "2.3.1", "2.12.2", "2.15.0", "2.16.0", "2.17.1"}
	for _, v := range yes {
		ok, err := in(v)
		if err != nil || !ok {
			t.Fatalf("%s should match, ok=%v err=%v", v, ok, err)
		}
	}
	for _, v := range no {
		ok, err := in(v)
		if err != nil || ok {
			t.Fatalf("%s should not match, ok=%v err=%v", v, ok, err)
		}
	}
	if _, err := InRange(SchemeMaven, "2.14.1.redhat-00001", ">=2.13.0 <2.15.0"); err == nil {
		t.Fatal("distro maven suffix must not parse")
	}
	if err := ValidateRange(SchemeMaven, ">=2.0-beta9 <2.3.1"); err != nil {
		t.Fatal(err)
	}
}

func TestSemverAndGo(t *testing.T) {
	ok, err := InRange(SchemeSemver, "1.2.3", ">=1.2.0 <1.3.0")
	if err != nil || !ok {
		t.Fatalf("semver match %v %v", ok, err)
	}
	ok, err = InRange(SchemeSemver, "1.2.3-rc.1", ">=1.2.3")
	if err != nil || ok {
		t.Fatalf("prerelease should be below the release: %v %v", ok, err)
	}
	if _, err := InRange(SchemeSemver, "1.2.3+build", "=1.2.3"); err == nil {
		t.Fatal("build metadata rejected")
	}
	if _, err := InRange(SchemeGo, "1.2.3", ">=v1.0.0"); err == nil {
		t.Fatal("go scheme requires v prefix")
	}
	ok, err = InRange(SchemeGo, "v1.2.3", ">=v1.2.0 <v1.3.0")
	if err != nil || !ok {
		t.Fatalf("go match %v %v", ok, err)
	}
}

func TestUnsupportedScheme(t *testing.T) {
	if Known("rpm") {
		t.Fatal("rpm is not an upstream scheme")
	}
	if _, err := InRange("deb", "1.2.3", ">=1.0.0"); err == nil {
		t.Fatal("expected unsupported scheme error")
	}
}
