// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 11, 9, 6, 0, 0, 0, time.UTC)

func keys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	privPEM, pubPEM, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

var sample = map[string][]byte{
	"packs/a.yaml": []byte("a: 1\n"),
	"osv/b.json":   []byte(`{"id":"GHSA-x"}`),
}

func TestRoundTrip(t *testing.T) {
	priv, pub := keys(t)
	raw, err := Build(sample, "2026.11.09", at, priv)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Build(sample, "2026.11.09", at, priv)
	if !bytes.Equal(raw, again) {
		t.Fatal("build is not deterministic")
	}
	v, err := Verify(bytes.NewReader(raw), pub)
	if err != nil {
		t.Fatal(err)
	}
	if v.Manifest.KBVersion != "2026.11.09" || len(v.Files) != 2 || string(v.Files["packs/a.yaml"]) != "a: 1\n" {
		t.Fatalf("%+v", v.Manifest)
	}
	dir := t.TempDir()
	target, err := Install(v, raw, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "files", "osv", "b.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(v, raw, dir); err == nil {
		t.Fatal("reinstall of the same kb_version was allowed")
	}
}

func TestWrongKey(t *testing.T) {
	priv, _ := keys(t)
	_, other := keys(t)
	raw, _ := Build(sample, "v1", at, priv)
	if _, err := Verify(bytes.NewReader(raw), other); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("err=%v", err)
	}
}

type member struct {
	name string
	data []byte
	typ  byte
	link string
}

// forge writes an arbitrary tar signed with priv over manifest m.
func forge(t *testing.T, priv ed25519.PrivateKey, m Manifest, members []member, sigOverride []byte) []byte {
	t.Helper()
	man, _ := json.MarshalIndent(m, "", "  ")
	sig := ed25519.Sign(priv, man)
	if sigOverride != nil {
		sig = sigOverride
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	all := append([]member{{name: manifestName, data: man}, {name: sigName, data: sig}}, members...)
	for _, mb := range all {
		typ := mb.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: mb.name, Mode: 0o644, Size: int64(len(mb.data)), Typeflag: typ, Linkname: mb.link, ModTime: at}
		if typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write(mb.data)
		}
	}
	tw.Close()
	return buf.Bytes()
}

func entry(p string, data []byte) Entry {
	s := sha256.Sum256(data)
	return Entry{Path: p, SHA256: hex.EncodeToString(s[:]), Size: int64(len(data))}
}

func TestRejectsTampering(t *testing.T) {
	priv, pub := keys(t)
	good := []byte("x: 1\n")
	base := func() Manifest {
		return Manifest{Format: FormatVersion, KBVersion: "v1", CreatedAt: at.Format(time.RFC3339), KeyID: KeyID(pub), Files: []Entry{entry("packs/a.yaml", good)}}
	}
	cases := map[string][]byte{
		"modified file": forge(t, priv, base(), []member{{name: "files/packs/a.yaml", data: []byte("x: 2\n")}}, nil),
		"unlisted extra": forge(t, priv, base(), []member{
			{name: "files/packs/a.yaml", data: good}, {name: "files/packs/evil.yaml", data: good}}, nil),
		"missing file": forge(t, priv, base(), nil, nil),
		"duplicate member": forge(t, priv, base(), []member{
			{name: "files/packs/a.yaml", data: good}, {name: "files/packs/a.yaml", data: good}}, nil),
		"traversal": func() []byte {
			m := base()
			m.Files = []Entry{entry("../a.yaml", good)}
			return forge(t, priv, m, []member{{name: "files/../a.yaml", data: good}}, nil)
		}(),
		"symlink": forge(t, priv, base(), []member{
			{name: "files/packs/a.yaml", data: good}, {name: "files/packs/l.yaml", typ: tar.TypeSymlink, link: "/etc/passwd"}}, nil),
		"unexpected top level": forge(t, priv, base(), []member{
			{name: "files/packs/a.yaml", data: good}, {name: "README", data: good}}, nil),
		"bad signature": forge(t, priv, base(), []member{{name: "files/packs/a.yaml", data: good}}, make([]byte, ed25519.SignatureSize)),
		"key id mismatch": func() []byte {
			m := base()
			m.KeyID = "00"
			return forge(t, priv, m, []member{{name: "files/packs/a.yaml", data: good}}, nil)
		}(),
		"hidden file": func() []byte {
			m := base()
			m.Files = []Entry{entry("packs/.a.yaml", good)}
			return forge(t, priv, m, []member{{name: "files/packs/.a.yaml", data: good}}, nil)
		}(),
		"wrong extension": func() []byte {
			m := base()
			m.Files = []Entry{entry("packs/run.sh", good)}
			return forge(t, priv, m, []member{{name: "files/packs/run.sh", data: good}}, nil)
		}(),
	}
	for name, raw := range cases {
		if _, err := Verify(bytes.NewReader(raw), pub); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Control: the same forger with honest inputs verifies.
	ok := forge(t, priv, base(), []member{{name: "files/packs/a.yaml", data: good}}, nil)
	if _, err := Verify(bytes.NewReader(ok), pub); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestBuildRejects(t *testing.T) {
	priv, _ := keys(t)
	if _, err := Build(sample, "v1", time.Time{}, priv); err == nil {
		t.Fatal("zero created_at accepted")
	}
	if _, err := Build(sample, "../v1", at, priv); err == nil {
		t.Fatal("bad kb_version accepted")
	}
	if _, err := Build(map[string][]byte{"/abs.yaml": nil}, "v1", at, priv); err == nil {
		t.Fatal("absolute path accepted")
	}
	if _, err := Build(map[string][]byte{}, "v1", at, priv); err == nil {
		t.Fatal("empty bundle accepted")
	}
}
