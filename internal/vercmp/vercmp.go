// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package vercmp compares a few upstream version schemes.
// Strings that do not parse return an error. Callers must treat that as
// unknown, not as "not in range". Distro package types are not handled here.
package vercmp

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Scheme names accepted by packs.
const (
	SchemeOpenSSH = "openssh_upstream"
	SchemeMaven   = "maven"
	SchemeSemver  = "semver"
	SchemeGo      = "go"
)

// Known reports whether the scheme is implemented.
func Known(scheme string) bool {
	switch scheme {
	case SchemeOpenSSH, SchemeMaven, SchemeSemver, SchemeGo:
		return true
	default:
		return false
	}
}

type token struct {
	num bool
	n   int
	q   string
	pre bool // semver prerelease identifier
}

// ValidateRange checks that every bound in expr parses for scheme.
func ValidateRange(scheme, expr string) error {
	parts, err := splitRange(expr)
	if err != nil {
		return err
	}
	for _, p := range parts {
		if _, err := parse(scheme, p.bound); err != nil {
			return fmt.Errorf("vercmp: bound %q: %w", p.bound, err)
		}
	}
	return nil
}

// InRange reports whether version satisfies every comparator in expr.
// expr is a space-separated AND of comparators. A list of expressions is
// OR'd by the caller. An unparsable version returns an error.
func InRange(scheme, version, expr string) (bool, error) {
	v, err := parse(scheme, version)
	if err != nil {
		return false, err
	}
	parts, err := splitRange(expr)
	if err != nil {
		return false, err
	}
	for _, p := range parts {
		b, err := parse(scheme, p.bound)
		if err != nil {
			return false, err
		}
		c := compare(scheme, v, b)
		switch p.op {
		case "<":
			if c >= 0 {
				return false, nil
			}
		case "<=":
			if c > 0 {
				return false, nil
			}
		case ">":
			if c <= 0 {
				return false, nil
			}
		case ">=":
			if c < 0 {
				return false, nil
			}
		case "=":
			if c != 0 {
				return false, nil
			}
		default:
			return false, fmt.Errorf("vercmp: bad operator %q", p.op)
		}
	}
	return true, nil
}

type comp struct {
	op    string
	bound string
}

func splitRange(expr string) ([]comp, error) {
	fields := strings.Fields(expr)
	if len(fields) == 0 {
		return nil, fmt.Errorf("vercmp: empty range")
	}
	out := make([]comp, 0, len(fields))
	for _, f := range fields {
		op, bound, err := splitOp(f)
		if err != nil {
			return nil, err
		}
		out = append(out, comp{op: op, bound: bound})
	}
	return out, nil
}

func splitOp(f string) (string, string, error) {
	ops := []string{">=", "<=", ">", "<", "="}
	for _, op := range ops {
		if strings.HasPrefix(f, op) && len(f) > len(op) {
			return op, f[len(op):], nil
		}
	}
	return "", "", fmt.Errorf("vercmp: comparator %q needs an operator and a version", f)
}

func parse(scheme, version string) ([]token, error) {
	switch scheme {
	case SchemeOpenSSH:
		return parseOpenSSH(version)
	case SchemeMaven:
		return parseMaven(version)
	case SchemeSemver:
		return parseSemver(version, false)
	case SchemeGo:
		return parseSemver(version, true)
	default:
		return nil, fmt.Errorf("vercmp: unsupported scheme %q", scheme)
	}
}

func parseOpenSSH(v string) ([]token, error) {
	// MAJOR.MINORpREVISION only. No epoch, no distro revision.
	major, rest, ok := strings.Cut(v, ".")
	if !ok {
		return nil, fmt.Errorf("openssh version %q", v)
	}
	minor, rev, ok := strings.Cut(rest, "p")
	if !ok || strings.ContainsAny(rev, ".-+~:") || strings.ContainsAny(minor, "p-+~:") {
		return nil, fmt.Errorf("openssh version %q", v)
	}
	nums := make([]int, 3)
	for i, part := range []string{major, minor, rev} {
		n, err := parseUint(part)
		if err != nil {
			return nil, fmt.Errorf("openssh version %q", v)
		}
		nums[i] = n
	}
	return []token{{num: true, n: nums[0]}, {num: true, n: nums[1]}, {num: true, n: nums[2]}}, nil
}

func parseMaven(v string) ([]token, error) {
	if v == "" || strings.ContainsAny(v, "+_:/ ") {
		return nil, fmt.Errorf("maven version %q", v)
	}
	lower := strings.ToLower(v)
	var toks []token
	i := 0
	for i < len(lower) {
		if lower[i] == '.' || lower[i] == '-' {
			i++
			continue
		}
		if lower[i] >= '0' && lower[i] <= '9' {
			j := i
			for j < len(lower) && lower[j] >= '0' && lower[j] <= '9' {
				j++
			}
			n, err := parseUint(lower[i:j])
			if err != nil {
				return nil, fmt.Errorf("maven version %q", v)
			}
			toks = append(toks, token{num: true, n: n})
			i = j
			continue
		}
		if lower[i] >= 'a' && lower[i] <= 'z' {
			j := i
			for j < len(lower) && lower[j] >= 'a' && lower[j] <= 'z' {
				j++
			}
			q, ok := canonicalQualifier(lower[i:j])
			if !ok {
				return nil, fmt.Errorf("maven qualifier %q in %q", lower[i:j], v)
			}
			toks = append(toks, token{q: q})
			i = j
			continue
		}
		return nil, fmt.Errorf("maven version %q", v)
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("maven version %q", v)
	}
	return toks, nil
}

func canonicalQualifier(q string) (string, bool) {
	switch q {
	case "a", "alpha":
		return "alpha", true
	case "b", "beta":
		return "beta", true
	case "m", "milestone":
		return "milestone", true
	case "rc", "cr":
		return "rc", true
	case "snapshot":
		return "snapshot", true
	case "ga", "final", "release":
		return "ga", true
	case "sp":
		return "sp", true
	default:
		return "", false
	}
}

func qualifierRank(q string) int {
	switch q {
	case "alpha":
		return 1
	case "beta":
		return 2
	case "milestone":
		return 3
	case "rc":
		return 4
	case "snapshot":
		return 5
	case "ga":
		return 6
	case "sp":
		return 7
	default:
		return 0
	}
}

func parseSemver(v string, requireV bool) ([]token, error) {
	if strings.Contains(v, "+") {
		return nil, fmt.Errorf("semver build metadata is rejected: %q", v)
	}
	if requireV {
		if !strings.HasPrefix(v, "v") {
			return nil, fmt.Errorf("go version %q requires a leading v", v)
		}
		v = strings.TrimPrefix(v, "v")
	} else {
		v = strings.TrimPrefix(v, "v")
	}
	main, pre, hasPre := strings.Cut(v, "-")
	parts := strings.Split(main, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("semver %q", v)
	}
	var toks []token
	for _, p := range parts {
		n, err := parseUint(p)
		if err != nil {
			return nil, fmt.Errorf("semver %q", v)
		}
		toks = append(toks, token{num: true, n: n})
	}
	if hasPre {
		if pre == "" {
			return nil, fmt.Errorf("semver %q", v)
		}
		for _, id := range strings.Split(pre, ".") {
			if id == "" || strings.ContainsFunc(id, func(r rune) bool {
				return !unicode.IsLetter(r) && !unicode.IsDigit(r)
			}) {
				return nil, fmt.Errorf("semver prerelease %q", v)
			}
			if n, err := parseUint(id); err == nil && isAllDigits(id) {
				toks = append(toks, token{num: true, n: n, pre: true})
			} else {
				toks = append(toks, token{q: id, pre: true})
			}
		}
	}
	return toks, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseUint(s string) (int, error) {
	if s == "" || len(s) > 9 {
		return 0, fmt.Errorf("bad number %q", s)
	}
	if len(s) > 1 && s[0] == '0' {
		// Leading zeros are rejected so "01" cannot compare equal to a
		// different textual version by accident. Maven usually allows them;
		// rejecting is the conservative parse failure (unknown).
		return 0, fmt.Errorf("leading zero %q", s)
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func compare(scheme string, a, b []token) int {
	switch scheme {
	case SchemeMaven:
		return compareMaven(a, b)
	case SchemeSemver, SchemeGo:
		return compareSemver(a, b)
	default:
		n := len(a)
		if len(b) > n {
			n = len(b)
		}
		for i := 0; i < n; i++ {
			av, bv := 0, 0
			if i < len(a) {
				av = a[i].n
			}
			if i < len(b) {
				bv = b[i].n
			}
			if av < bv {
				return -1
			}
			if av > bv {
				return 1
			}
		}
		return 0
	}
}

func compareMaven(a, b []token) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var ta, tb *token
		if i < len(a) {
			ta = &a[i]
		}
		if i < len(b) {
			tb = &b[i]
		}
		if c := compareMavenTok(ta, tb); c != 0 {
			return c
		}
	}
	return 0
}

func compareMavenTok(a, b *token) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -compareMavenTok(b, nil)
	}
	if b == nil {
		if a.num {
			if a.n == 0 {
				return 0
			}
			return 1
		}
		// A qualifier without the other side is older than a release
		// (1.0-beta < 1.0) except ga, which is the release token itself.
		if a.q == "ga" {
			return 0
		}
		return -1
	}
	if a.num && b.num {
		if a.n < b.n {
			return -1
		}
		if a.n > b.n {
			return 1
		}
		return 0
	}
	if !a.num && !b.num {
		ra, rb := qualifierRank(a.q), qualifierRank(b.q)
		if ra < rb {
			return -1
		}
		if ra > rb {
			return 1
		}
		return 0
	}
	// Qualifier versus number: qualifiers sort before the release number
	// at that position (1.0-beta < 1.0.1 is handled by the missing-token
	// rule on a shorter list; here both tokens exist).
	if a.num {
		return 1
	}
	return -1
}

func compareSemver(a, b []token) int {
	// First three tokens are the core version. A prerelease is less than
	// the matching release. Identifiers compare numeric-to-numeric,
	// numeric lower than non-numeric, then ASCII.
	an, bn := splitPre(a), splitPre(b)
	core := 3
	for i := 0; i < core; i++ {
		if an.core[i].n < bn.core[i].n {
			return -1
		}
		if an.core[i].n > bn.core[i].n {
			return 1
		}
	}
	if len(an.pre) == 0 && len(bn.pre) == 0 {
		return 0
	}
	if len(an.pre) == 0 {
		return 1
	}
	if len(bn.pre) == 0 {
		return -1
	}
	n := len(an.pre)
	if len(bn.pre) < n {
		n = len(bn.pre)
	}
	for i := 0; i < n; i++ {
		if c := compareSemverID(an.pre[i], bn.pre[i]); c != 0 {
			return c
		}
	}
	if len(an.pre) < len(bn.pre) {
		return -1
	}
	if len(an.pre) > len(bn.pre) {
		return 1
	}
	return 0
}

type semParts struct {
	core []token
	pre  []token
}

func splitPre(toks []token) semParts {
	core := toks
	var pre []token
	for i, t := range toks {
		if t.pre {
			core = toks[:i]
			pre = toks[i:]
			break
		}
	}
	return semParts{core: core, pre: pre}
}

func compareSemverID(a, b token) int {
	if a.num && b.num {
		if a.n < b.n {
			return -1
		}
		if a.n > b.n {
			return 1
		}
		return 0
	}
	if a.num && !b.num {
		return -1
	}
	if !a.num && b.num {
		return 1
	}
	if a.q < b.q {
		return -1
	}
	if a.q > b.q {
		return 1
	}
	return 0
}
