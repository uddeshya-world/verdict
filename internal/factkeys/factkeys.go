// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package factkeys holds the closed value sets of host fact keys. The host
// importer validates against them and the engine uses them to tell an
// out-of-domain value from a real negative.
package factkeys

// Closed maps a fact key to the only values it may hold. Keys that take
// free-form values (config.sshd.LoginGraceTime) are absent.
var Closed = map[string][]string{
	"libc.family":                    {"glibc", "musl"},
	"process.listening.sshd":         {"true", "false"},
	"service.socket_activation.sshd": {"true", "false"},
	"process.sshd.links_liblzma":     {"true", "false"},
}

// InDomain reports whether v is allowed for key. The second result is false
// when the key has no closed set.
func InDomain(key, v string) (ok, known bool) {
	allowed, known := Closed[key]
	if !known {
		return true, false
	}
	for _, a := range allowed {
		if a == v {
			return true, true
		}
	}
	return false, true
}

// PortLists are fact keys whose value is a canonical TCP/UDP port list. A
// pack may name one of these as exposure.port_fact.
var PortLists = map[string]struct{}{
	"config.sshd.Port": {},
}

// MaxPorts caps a port list. sshd itself accepts at most 256 listen
// addresses; a longer list is refused rather than truncated.
const MaxPorts = 64

// IsPortList reports whether key holds a canonical port list.
func IsPortList(key string) bool {
	_, ok := PortLists[key]
	return ok
}

// ParsePortList parses the canonical port-list encoding: one or more decimal
// ports in 1..65535, without sign, leading zeros, or white space, joined by a
// single comma, strictly ascending (so no duplicates), at most MaxPorts
// entries. "22" and "22,2222" are canonical; "022", "22 ", "2222,22",
// "22,22", "22,", "0", and "65536" are not. Every other spelling is an
// error, never a best-effort parse.
func ParsePortList(v string) ([]int, error) {
	if v == "" {
		return nil, errPort("empty port list")
	}
	var out []int
	n, digits := 0, 0
	flush := func() error {
		if digits == 0 {
			return errPort("empty port in list")
		}
		if n < 1 || n > 65535 {
			return errPort("port out of range 1-65535")
		}
		if len(out) > 0 && n <= out[len(out)-1] {
			return errPort("ports must be strictly ascending")
		}
		if len(out) == MaxPorts {
			return errPort("too many ports")
		}
		out = append(out, n)
		n, digits = 0, 0
		return nil
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			if digits == 0 && c == '0' && i+1 < len(v) && v[i+1] >= '0' && v[i+1] <= '9' {
				return nil, errPort("leading zero")
			}
			digits++
			if digits > 5 {
				return nil, errPort("port out of range 1-65535")
			}
			n = n*10 + int(c-'0')
		case c == ',':
			if err := flush(); err != nil {
				return nil, err
			}
		default:
			return nil, errPort("unexpected character")
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

type portErr string

func (e portErr) Error() string { return "port list: " + string(e) }

func errPort(s string) error { return portErr(s) }
