// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import "fmt"

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
		return base + " Pack hint: " + packHint
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
