// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package factkeys

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestParsePortListCanonical(t *testing.T) {
	for in, want := range map[string][]int{
		"22":          {22},
		"1":           {1},
		"65535":       {65535},
		"22,2222":     {22, 2222},
		"22,443,2222": {22, 443, 2222},
		"2222,65535":  {2222, 65535},
	} {
		got, err := ParsePortList(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v %v want %v", in, got, err, want)
		}
	}
}

func TestParsePortListRejectsNonCanonical(t *testing.T) {
	for _, in := range []string{
		"", " ", "0", "00", "022", "65536", "99999", "123456", "-22", "+22",
		"22 ", " 22", "22, 2222", "22,", ",22", "22,,2222", "2222,22", "22,22",
		"22;2222", "22 2222", "0x16", "22.0", "２２", "22\n", "tcp/22", "ssh",
	} {
		if got, err := ParsePortList(in); err == nil {
			t.Errorf("%q accepted as %v", in, got)
		}
	}
}

func TestParsePortListCap(t *testing.T) {
	var ps []string
	for i := 1; i <= MaxPorts; i++ {
		ps = append(ps, strconv.Itoa(i))
	}
	if _, err := ParsePortList(strings.Join(ps, ",")); err != nil {
		t.Fatalf("MaxPorts entries refused: %v", err)
	}
	ps = append(ps, strconv.Itoa(MaxPorts+1))
	if _, err := ParsePortList(strings.Join(ps, ",")); err == nil {
		t.Fatal("MaxPorts+1 entries accepted")
	}
}

func TestLibcDomainIsClosed(t *testing.T) {
	for _, v := range []string{"uclibc", "uClibc", "bionic", "freebsd", "libc", "Glibc", "MUSL", " musl", ""} {
		if ok, known := InDomain("libc.family", v); !known || ok {
			t.Errorf("libc.family %q in domain", v)
		}
	}
}
