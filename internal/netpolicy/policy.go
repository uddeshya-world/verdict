// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package netpolicy is the only place a future collector may dial.
// The default policy denies every address. v0.1's drill path does not call Dial.
package netpolicy

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// ErrDenied is returned before any network call when the address is not allowlisted.
var ErrDenied = fmt.Errorf("netpolicy: outbound dial denied by default")

// DialFunc matches net.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Policy is an exact address allowlist. Empty means deny all.
type Policy struct {
	Allow []string
}

// Default is the deny-all policy.
func Default() Policy { return Policy{} }

// Allows reports whether address is an exact allowlist entry.
func (p Policy) Allows(address string) bool {
	for _, a := range p.Allow {
		if a == address {
			return true
		}
	}
	return false
}

// Dial dials only allowlisted addresses. A nil dialer is the real net.Dialer.
// Denied addresses never call dial.
func (p Policy) Dial(ctx context.Context, network, address string, dial DialFunc) (net.Conn, error) {
	if !p.Allows(address) {
		return nil, fmt.Errorf("%w: %s %s", ErrDenied, network, address)
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return dial(ctx, network, address)
}

// String renders the allowlist for diagnostics. It does not include secrets.
func (p Policy) String() string {
	if len(p.Allow) == 0 {
		return "netpolicy(deny-all)"
	}
	return "netpolicy(allow=" + strings.Join(p.Allow, ",") + ")"
}
