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
