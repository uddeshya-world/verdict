// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package purl parses the subset of Package URLs the engine matches on.
package purl

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// PURL is a package identifier.
type PURL struct {
	Type      string
	Namespace string
	Name      string
	Version   string
	Raw       string
}

// Parse splits a package URL. Qualifiers and subpaths are ignored for matching
// and rejected if this is used as a pattern; versions may be present.
func Parse(raw string) (PURL, error) {
	if !strings.HasPrefix(raw, "pkg:") {
		return PURL{}, fmt.Errorf("purl: %q does not start with pkg:", raw)
	}
	s := strings.TrimPrefix(raw, "pkg:")
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	typ, rest, ok := strings.Cut(s, "/")
	if !ok || typ == "" || rest == "" {
		return PURL{}, fmt.Errorf("purl: malformed %q", raw)
	}
	version := ""
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		version = rest[i+1:]
		rest = rest[:i]
		if version == "" || rest == "" {
			return PURL{}, fmt.Errorf("purl: malformed %q", raw)
		}
	}
	parts := strings.Split(rest, "/")
	name := parts[len(parts)-1]
	if name == "" {
		return PURL{}, fmt.Errorf("purl: malformed %q", raw)
	}
	ns := strings.Join(parts[:len(parts)-1], "/")
	return PURL{Type: typ, Namespace: ns, Name: name, Version: version, Raw: raw}, nil
}

// Match reports whether p matches a versionless pattern.
// An empty pattern namespace matches any namespace.
func Match(pattern string, p PURL) bool {
	pat, err := Parse(pattern)
	if err != nil {
		return false
	}
	if !strings.EqualFold(pat.Type, p.Type) || pat.Name != p.Name {
		return false
	}
	if pat.Namespace == "" {
		return true
	}
	return pat.Namespace == p.Namespace
}

// Canonical decodes percent-escapes, re-encodes reserved characters, lowercases the type, and sorts qualifiers.
// The type is case-insensitive in the purl spec. Namespace and name keep their case here;
// FoldKey and Related are the case-insensitive views used to keep variants in scope.
// Reserved characters are % @ ? # / & =. A colon in a version stays decoded so 1%3A8.9 and 1:8.9 match.
// Qualifiers are kept. An advisory without them does not match a package URL that has them.
// Epoch stays in the qualifier when that is where the source put it.
func Canonical(raw string) (string, error) {
	if !strings.HasPrefix(raw, "pkg:") {
		return "", fmt.Errorf("purl: %q does not start with pkg:", raw)
	}
	rest := strings.TrimPrefix(raw, "pkg:")
	sub := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		sub = rest[i+1:]
		rest = rest[:i]
	}
	qual := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		qual = rest[i+1:]
		rest = rest[:i]
	}
	typ, path, ok := strings.Cut(rest, "/")
	if !ok || typ == "" || path == "" {
		return "", fmt.Errorf("purl: malformed %q", raw)
	}
	typ, err := unescape(typ)
	if err != nil {
		return "", err
	}
	typ = encode(strings.ToLower(typ))
	version := ""
	if i := strings.LastIndex(path, "@"); i >= 0 {
		version = path[i+1:]
		path = path[:i]
		if version == "" || path == "" {
			return "", fmt.Errorf("purl: malformed %q", raw)
		}
		version, err = unescape(version)
		if err != nil {
			return "", err
		}
		version = encode(version)
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		parts[i], err = unescape(part)
		if err != nil || parts[i] == "" {
			return "", fmt.Errorf("purl: malformed %q", raw)
		}
		parts[i] = encode(parts[i])
	}
	q, err := canonicalQualifiers(qual)
	if err != nil {
		return "", err
	}
	out := "pkg:" + typ + "/" + strings.Join(parts, "/")
	if version != "" {
		out += "@" + version
	}
	if q != "" {
		out += "?" + q
	}
	if sub != "" {
		decoded, err := unescape(sub)
		if err != nil {
			return "", err
		}
		out += "#" + encode(decoded)
	}
	return out, nil
}

// Same reports whether two package URLs have the same canonical form.
// A URL that cannot be canonicalized matches only its own bytes.
func Same(a, b string) bool {
	ca, ea := Canonical(a)
	cb, eb := Canonical(b)
	if ea != nil || eb != nil {
		return a == b
	}
	return ca == cb
}

func canonicalQualifiers(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	pairs := strings.Split(raw, "&")
	type pair struct{ k, v string }
	out := make([]pair, 0, len(pairs))
	seen := map[string]struct{}{}
	for _, item := range pairs {
		k, v, ok := strings.Cut(item, "=")
		if !ok || k == "" {
			return "", fmt.Errorf("purl: malformed qualifier %q", item)
		}
		var err error
		k, err = unescape(k)
		if err != nil {
			return "", err
		}
		v, err = unescape(v)
		if err != nil {
			return "", err
		}
		if _, dup := seen[k]; dup {
			return "", fmt.Errorf("purl: duplicate qualifier %q", k)
		}
		seen[k] = struct{}{}
		out = append(out, pair{encode(k), encode(v)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].k < out[j].k })
	parts := make([]string, len(out))
	for i, p := range out {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&"), nil
}

// Decode percent-decodes a package-URL component. Plus signs are kept.
func Decode(s string) (string, error) {
	return unescape(s)
}

func encode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '%' || c == '@' || c == '?' || c == '#' || c == '/' || c == '&' || c == '=' {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func unescape(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("purl: truncated escape in %q", s)
		}
		n, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", fmt.Errorf("purl: bad escape in %q", s)
		}
		b.WriteByte(byte(n))
		i += 2
	}
	return b.String(), nil
}

// DistroType reports whether version sorting must not be used.
func DistroType(typ string) bool {
	switch strings.ToLower(typ) {
	case "deb", "rpm", "apk":
		return true
	default:
		return false
	}
}

// FoldName is the comparison form of a package name: percent-decoded,
// trimmed of white space and of leading or trailing separators, and case-folded.
// It is used only to widen what counts as the same component, never to
// prove that a package is a different one.
func FoldName(name string) string {
	if dec, err := unescape(name); err == nil {
		name = dec
	}
	name = strings.TrimSpace(name)
	name = strings.Trim(name, "-_.+ \t")
	return strings.ToLower(name)
}

func squash(folded string) string {
	return strings.Map(func(r rune) rune {
		if isSep(r) {
			return -1
		}
		return r
	}, folded)
}

func isSep(r rune) bool {
	return !unicode.IsLetter(r) && !unicode.IsDigit(r)
}

func tokens(folded string) []string {
	return strings.FieldsFunc(folded, isSep)
}

// FoldKey is a case-folded identity for a package URL: canonical form with the
// namespace, version, and qualifiers lowercased and the name folded by FoldName.
// Two URLs with the same FoldKey are spellings of one package for conflict
// detection. A URL that cannot be canonicalized returns its trimmed, lowercased bytes.
func FoldKey(raw string) string {
	c, err := Canonical(raw)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	rest := strings.TrimPrefix(c, "pkg:")
	tail := ""
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		tail = rest[i:]
		rest = rest[:i]
	}
	typ, path, _ := strings.Cut(rest, "/")
	version := ""
	if i := strings.LastIndex(path, "@"); i >= 0 {
		version = path[i:]
		path = path[:i]
	}
	parts := strings.Split(path, "/")
	parts[len(parts)-1] = encode(FoldName(parts[len(parts)-1]))
	return "pkg:" + typ + "/" + strings.ToLower(strings.Join(parts[:len(parts)-1], "/")) + "/" + parts[len(parts)-1] + strings.ToLower(version+tail)
}

// SameFolded reports whether two package URLs have the same FoldKey.
func SameFolded(a, b string) bool {
	return FoldKey(a) == FoldKey(b)
}

// Related reports whether p could be the component a versionless pattern
// names without matching it exactly. It is deliberately wide: a related
// package keeps the component in scope (unknown), it is never version-sorted.
//
//   - The folded names are equal, or equal once separators are removed,
//     under any type or namespace (OpenSSH, "openssh ", open-ssh, a pypi
//     package named like a deb package).
//   - The pattern's name tokens appear in order inside the package's name
//     tokens (openssh-portable, openssh-server-pam), when the package type is
//     generic (free-form names) or both types are distro types. Language
//     ecosystems and distro packages against a generic pattern are excluded,
//     because their names are curated and openssh-client is not sshd.
func Related(pattern string, p PURL) bool {
	pat, err := Parse(pattern)
	if err != nil {
		return false
	}
	pn, qn := FoldName(p.Name), FoldName(pat.Name)
	if pn == "" || qn == "" {
		return false
	}
	if pn == qn || squash(pn) == squash(qn) {
		return true
	}
	pt, qt := strings.ToLower(p.Type), strings.ToLower(pat.Type)
	if pt != "generic" && !(DistroType(pt) && DistroType(qt)) {
		return false
	}
	return containsRun(tokens(pn), tokens(qn))
}

func containsRun(hay, needle []string) bool {
	if len(needle) == 0 || len(needle) > len(hay) {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		ok := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
