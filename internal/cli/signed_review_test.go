// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/bundle"
	"github.com/uddeshya-world/verdict/internal/pack"
)

// reviewKit is a temp tree for signed-review tests: packs/<file>.yaml (the
// openssh pack promoted to reviewed by two named people), packs/reviewer-keys
// with Alice's and Bob's public keys, private keys outside packs/, and
// packs/reviews/<pack_id>/.
type reviewKit struct {
	dir, packs, keys, reviews, packPath, packID string
	priv                                        map[string]string // name -> private key path
	ids                                         map[string]string // name -> key id
}

const (
	alice = "Alice Example"
	bob   = "Bob Example"
	mal   = "Mallory Example"
	at    = "2026-11-13T10:00:00Z"
)

func newReviewKit(t *testing.T) *reviewKit {
	t.Helper()
	k := &reviewKit{dir: t.TempDir(), priv: map[string]string{}, ids: map[string]string{}}
	k.packs = filepath.Join(k.dir, "packs")
	k.keys = filepath.Join(k.packs, "reviewer-keys")
	if err := os.MkdirAll(k.keys, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(moduleRoot(t), "packs/draft/ecp-cve-2024-6387-openssh.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	y := strings.Replace(string(src), "  status: draft\n", "  status: reviewed\n", 1)
	y = strings.Replace(y, "  reviewers: []\n", "  reviewers:\n    - name: "+alice+"\n    - name: "+bob+"\n", 1)
	k.packPath = filepath.Join(k.packs, "ssh.yaml")
	if err := os.WriteFile(k.packPath, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := pack.Load(k.packPath, []byte(y))
	if err != nil {
		t.Fatal(err)
	}
	k.packID = p.Metadata.ID
	k.reviews = filepath.Join(k.packs, "reviews")
	if err := os.MkdirAll(filepath.Join(k.reviews, k.packID), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{alice, bob, mal} {
		privPEM, pubPEM, err := bundle.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := bundle.ParsePublicKey(pubPEM)
		id := bundle.KeyID(pub)
		k.ids[name] = id
		k.priv[name] = filepath.Join(k.dir, strings.Fields(name)[0]+".key")
		os.WriteFile(k.priv[name], privPEM, 0o600)
		if name != mal { // Mallory's key is not trusted.
			os.WriteFile(filepath.Join(k.keys, id+".pub"), pubPEM, 0o644)
		}
	}
	return k
}

func (k *reviewKit) sign(t *testing.T, signer, name, packPath string) pack.ReviewAttestation {
	t.Helper()
	o, err := runCLI("pack", "sign-review", "--pack", packPath, "--key", k.priv[signer], "--reviewer", name,
		"--statement", "Checked every check against the cited advisories.", "--reviewed-at", at)
	if err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	var a pack.ReviewAttestation
	if err := json.Unmarshal([]byte(o), &a); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	return a
}

func (k *reviewKit) hash(t *testing.T, path string) string {
	t.Helper()
	data, _ := os.ReadFile(path)
	p, err := pack.Load(path, data)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := pack.ContentSHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func (k *reviewKit) record(t *testing.T, name string, sha string, rs ...pack.ReviewAttestation) string {
	t.Helper()
	b, _ := json.Marshal(pack.ReviewRecord{PackID: k.packID, PackSHA256: sha, Reviewers: rs})
	p := filepath.Join(k.reviews, k.packID, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func (k *reviewKit) review(rec string, extra ...string) []string {
	return append([]string{"pack", "review", "--pack", k.packPath, "--record", rec, "--reviewer-keys", k.keys, "--require-signatures"}, extra...)
}

func TestSignedReviewVerifies(t *testing.T) {
	k := newReviewKit(t)
	sha := k.hash(t, k.packPath)
	a, b := k.sign(t, alice, alice, k.packPath), k.sign(t, bob, bob, k.packPath)
	if a.KeyID != k.ids[alice] || a.Signature == "" {
		t.Fatalf("%+v", a)
	}
	rec := k.record(t, "ok.json", sha, a, b)
	o, err := runCLI(k.review(rec)...)
	if err != nil || !strings.Contains(o, "signatures_verified=2") {
		t.Fatalf("%v\n%s", err, o)
	}
	o, err = runCLI(k.review(rec, "--json")...)
	if err != nil || !strings.Contains(o, `"signatures_verified": 2`) {
		t.Fatalf("%v\n%s", err, o)
	}
}

// Every way to fake a signed review record fails with exit 2.
func TestSignedReviewRefusals(t *testing.T) {
	k := newReviewKit(t)
	sha := k.hash(t, k.packPath)
	a, b := k.sign(t, alice, alice, k.packPath), k.sign(t, bob, bob, k.packPath)
	unsigned := func(x pack.ReviewAttestation) pack.ReviewAttestation { x.KeyID, x.Signature = "", ""; return x }

	// Unsigned reviewers.
	rec := k.record(t, "r.json", sha, unsigned(a), unsigned(b))
	wantExit2(t, "is not signed", k.review(rec)...)
	wantExit2(t, "is not signed", k.review(k.record(t, "r.json", sha, a, unsigned(b)))...)
	wantExit2(t, "--require-signatures needs --reviewer-keys", "pack", "review", "--pack", k.packPath, "--record", rec, "--require-signatures")
	// Without --require-signatures an unsigned record still passes the old check.
	if o, err := runCLI("pack", "review", "--pack", k.packPath, "--record", rec, "--reviewer-keys", k.keys); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}

	// Fabricated signature bytes.
	fake := b
	junk := make([]byte, 64)
	rand.Read(junk)
	fake.Signature = base64.StdEncoding.EncodeToString(junk)
	wantExit2(t, "does not verify", k.review(k.record(t, "r.json", sha, a, fake))...)
	fake.Signature = "not base64!"
	wantExit2(t, "not base64 Ed25519", k.review(k.record(t, "r.json", sha, a, fake))...)
	// key_id without signature.
	half := b
	half.Signature = ""
	wantExit2(t, "needs both key_id and signature", k.review(k.record(t, "r.json", sha, a, half))...)
	// Mallory signs as Bob with an untrusted key.
	wantExit2(t, "no trusted key", k.review(k.record(t, "r.json", sha, a, k.sign(t, mal, bob, k.packPath)))...)
	// Alice signs for both names with her one key.
	wantExit2(t, "same key", k.review(k.record(t, "r.json", sha, a, k.sign(t, alice, bob, k.packPath)))...)
	// Alice's signature moved onto Bob's entry.
	moved := b
	moved.KeyID, moved.Signature = a.KeyID, a.Signature
	wantExit2(t, "does not verify", "pack", "review", "--pack", k.packPath, "--record", k.record(t, "r.json", sha, unsigned(a), moved), "--reviewer-keys", k.keys)
	moved2 := b
	moved2.Signature = a.Signature
	wantExit2(t, "does not verify", k.review(k.record(t, "r.json", sha, a, moved2))...)
	// A key file whose content is not the key its name says.
	wrong := filepath.Join(t.TempDir(), "keys")
	os.MkdirAll(wrong, 0o755)
	bobPub, _ := os.ReadFile(filepath.Join(k.keys, k.ids[bob]+".pub"))
	alicePub, _ := os.ReadFile(filepath.Join(k.keys, k.ids[alice]+".pub"))
	os.WriteFile(filepath.Join(wrong, k.ids[alice]+".pub"), bobPub, 0o644)
	os.WriteFile(filepath.Join(wrong, k.ids[bob]+".pub"), alicePub, 0o644)
	ok := k.record(t, "ok.json", sha, a, b)
	wantExit2(t, "holds key", "pack", "review", "--pack", k.packPath, "--record", ok, "--reviewer-keys", wrong, "--require-signatures")
	// A path-like key id is refused before any file is opened.
	trav := b
	trav.KeyID = "../../etc/passwd"
	wantExit2(t, "key_id", k.review(k.record(t, "r.json", sha, a, trav))...)

	// Tampered pack: the signed record no longer matches the content hash.
	data, _ := os.ReadFile(k.packPath)
	tampered := filepath.Join(k.dir, "tampered.yaml")
	os.WriteFile(tampered, []byte(strings.Replace(string(data), "(regreSSHion) — draft", "(regreSSHion) — edited", 1)), 0o644)
	wantExit2(t, "pack_sha256 does not match", "pack", "review", "--pack", tampered, "--record", ok, "--reviewer-keys", k.keys, "--require-signatures")
	// A forger rewrites pack_sha256 to the tampered content; the signatures
	// were made over the old hash and fail.
	forged := k.record(t, "r.json", k.hash(t, tampered), a, b)
	wantExit2(t, "does not verify", "pack", "review", "--pack", tampered, "--record", forged, "--reviewer-keys", k.keys, "--require-signatures")

	// sign-review refusals.
	wantExit2(t, "are required", "pack", "sign-review", "--pack", k.packPath, "--key", k.priv[alice], "--reviewer", alice)
	wantExit2(t, "synthetic-reviewer-* names", "pack", "sign-review", "--pack", k.packPath, "--key", k.priv[alice],
		"--reviewer", "synthetic-reviewer-alpha", "--statement", "x", "--reviewed-at", at)
	wantExit2(t, "reviewed_at", "pack", "sign-review", "--pack", k.packPath, "--key", k.priv[alice],
		"--reviewer", alice, "--statement", "x", "--reviewed-at", "today")
	wantExit2(t, "PRIVATE KEY", "pack", "sign-review", "--pack", k.packPath, "--key", filepath.Join(k.keys, k.ids[alice]+".pub"),
		"--reviewer", alice, "--statement", "x", "--reviewed-at", at)
}

// The CI gate: a reviewed real pack needs a signed record; drafts and
// synthetic packs pass; the repository passes today.
func TestCheckReviewsGate(t *testing.T) {
	k := newReviewKit(t)
	gate := func() []string {
		return []string{"pack", "check-reviews", "--packs", k.packs, "--reviews", k.reviews, "--reviewer-keys", k.keys}
	}
	wantExit2(t, "failed", gate()...) // no record yet
	sha := k.hash(t, k.packPath)
	a, b := k.sign(t, alice, alice, k.packPath), k.sign(t, bob, bob, k.packPath)
	unsigned := func(x pack.ReviewAttestation) pack.ReviewAttestation { x.KeyID, x.Signature = "", ""; return x }

	rec := k.record(t, "1.json", sha, unsigned(a), unsigned(b))
	wantExit2(t, "failed", gate()...)
	// Mallory's record with her untrusted key under Bob's name.
	k.record(t, "1.json", sha, a, k.sign(t, mal, bob, k.packPath))
	wantExit2(t, "failed", gate()...)
	// Record reviewers differ from the pack's.
	k.record(t, "1.json", sha, a, k.sign(t, mal, mal, k.packPath))
	wantExit2(t, "failed", gate()...)

	k.record(t, "1.json", sha, a, b)
	o, err := runCLI(gate()...)
	if err != nil || !strings.Contains(o, "reviewed_signed=1 failed=0") {
		t.Fatalf("%v\n%s", err, o)
	}
	o, err = runCLI(append(gate(), "--json")...)
	if err != nil || !strings.Contains(o, `"reviewed": [`) {
		t.Fatalf("%v\n%s", err, o)
	}
	// Tamper with the pack after signing: the gate fails.
	data, _ := os.ReadFile(k.packPath)
	os.WriteFile(k.packPath, []byte(strings.Replace(string(data), "(regreSSHion) — draft", "(regreSSHion) — edited", 1)), 0o644)
	wantExit2(t, "failed", gate()...)
	// A draft-only tree passes trivially.
	os.WriteFile(k.packPath, []byte(strings.Replace(strings.Replace(string(data), "  status: reviewed\n", "  status: draft\n", 1),
		"  reviewers:\n    - name: "+alice+"\n    - name: "+bob+"\n", "  reviewers: []\n", 1)), 0o644)
	os.Remove(rec)
	if o, err := runCLI(gate()...); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}

	// The repository: synthetic reviewed packs are exempt, real packs are draft.
	root := moduleRoot(t)
	o, err = runCLI("pack", "check-reviews", "--packs", filepath.Join(root, "packs"),
		"--reviews", filepath.Join(root, "packs/reviews"), "--reviewer-keys", filepath.Join(root, "packs/reviewer-keys"))
	if err != nil || !strings.Contains(o, "failed=0") {
		t.Fatalf("repository gate: %v\n%s", err, o)
	}
}
