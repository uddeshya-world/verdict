// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"strconv"
	"strings"
)

// leafHint renders the catalog hint for a leaf reason. A code with no catalog
// entry (none should exist; reasons_test.go checks) falls back to a generic
// line that still names the code.
func leafHint(reason, checkID, detail, packHint string) string {
	var base string
	if info, ok := Reasons[reason]; ok {
		base = renderHint(info.Hint, checkID, detail)
	} else {
		base = fmt.Sprintf("Check %s is unresolved (%s).", checkID, reason)
	}
	if packHint != "" {
		return base + packHintSep + packHint
	}
	return base
}

// decisionHint returns the catalog text for a decision or exposure reason.
// A code with no catalog entry is returned bare.
func decisionHint(reason string) string {
	info, ok := Reasons[reason]
	if !ok {
		return reason
	}
	if info.DecisionHint != "" {
		return info.DecisionHint
	}
	return info.Hint
}

// packHintSep joins a rendered catalog hint and a pack's resolution_hint.
const packHintSep = " Pack hint: "

// ParseLeafHint splits a leaf hint as leafHint renders it into the detail and
// the pack's resolution_hint text. It succeeds only where the split is
// unambiguous: the reason is a leaf catalog entry, and its template uses
// {detail_q} (a Go-quoted detail) or no detail at all. A template that puts
// the raw {detail} in prose cannot be split reliably and returns ok false.
// hasDetail reports whether the template carries a detail.
func ParseLeafHint(reason, checkID, hint string) (detail string, hasDetail bool, packHint string, ok bool) {
	info, known := Reasons[reason]
	if !known || info.Kind != KindLeaf {
		return "", false, "", false
	}
	tmpl := info.Hint
	if strings.Contains(tmpl, "{detail}") || strings.Count(tmpl, "{detail_q}") > 1 {
		return "", false, "", false
	}
	rest := hint
	if i := strings.Index(tmpl, "{detail_q}"); i >= 0 {
		head := renderHint(tmpl[:i], checkID, "")
		tail := renderHint(tmpl[i+len("{detail_q}"):], checkID, "")
		if !strings.HasPrefix(rest, head) {
			return "", false, "", false
		}
		rest = rest[len(head):]
		q, err := strconv.QuotedPrefix(rest)
		if err != nil {
			return "", false, "", false
		}
		if detail, err = strconv.Unquote(q); err != nil {
			return "", false, "", false
		}
		rest = rest[len(q):]
		if !strings.HasPrefix(rest, tail) {
			return "", false, "", false
		}
		rest = rest[len(tail):]
		hasDetail = true
	} else {
		base := renderHint(tmpl, checkID, "")
		if !strings.HasPrefix(rest, base) {
			return "", false, "", false
		}
		rest = rest[len(base):]
	}
	switch {
	case rest == "":
		return detail, hasDetail, "", true
	case strings.HasPrefix(rest, packHintSep):
		return detail, hasDetail, rest[len(packHintSep):], true
	}
	return "", false, "", false
}
