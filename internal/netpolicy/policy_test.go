// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package netpolicy

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestDefaultDeniesWithoutDialing(t *testing.T) {
	called := false
	_, err := Default().Dial(context.Background(), "tcp", "example.com:443", func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, errors.New("should not dial")
	})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("err %v", err)
	}
	if called {
		t.Fatal("deny path dialed")
	}
}

func TestAllowCallsDialer(t *testing.T) {
	called := false
	p := Policy{Allow: []string{"127.0.0.1:1"}}
	_, err := p.Dial(context.Background(), "tcp", "127.0.0.1:1", func(_ context.Context, network, address string) (net.Conn, error) {
		called = true
		if network != "tcp" || address != "127.0.0.1:1" {
			t.Fatalf("dial %s %s", network, address)
		}
		return nil, errors.New("injected")
	})
	if err == nil || !called {
		t.Fatalf("called %v err %v", called, err)
	}
	if _, err := p.Dial(context.Background(), "tcp", "127.0.0.1:2", func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("non-allowlisted address dialed")
		return nil, nil
	}); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
}
