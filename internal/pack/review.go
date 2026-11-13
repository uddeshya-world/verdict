// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/uddeshya-world/verdict/internal/bundle"
)

// ReviewAttestation is one human's statement about one pack file.
// The name is whoever the operator records. This package does not
// check that the person exists.
type ReviewAttestation struct {
	Name       string `json:"name"`
	ReviewedAt string `json:"reviewed_at"`
	Statement  string `json:"statement"`
	// KeyID and Signature are optional. Signature is base64 Ed25519 over
	// ReviewMessage, made with the reviewer's own key; KeyID is
	// bundle.KeyID of the matching public key.
	KeyID     string `json:"key_id,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// ReviewSignatureDomain starts every signed review message.
const ReviewSignatureDomain = "verdict-pack-review/v1"

var keyIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ReviewMessage is the exact byte string a reviewer signs: the domain, the
// pack id, the content hash, and the reviewer name (trimmed), each followed
// by a newline. reviewed_at and statement are not signed.
func ReviewMessage(packID, packSHA256, name string) []byte {
	return []byte(ReviewSignatureDomain + "\n" + packID + "\n" + packSHA256 + "\n" + strings.TrimSpace(name) + "\n")
}

// SignReview returns a signed attestation for one reviewer. It refuses a
// name that is empty, multi-line, or a synthetic-reviewer-* name on a real
// pack, and the reverse.
func SignReview(p *Pack, priv ed25519.PrivateKey, name, reviewedAt, statement string) (*ReviewAttestation, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "\x00\r\n") || len(name) > 256 {
		return nil, fmt.Errorf("pack sign-review: reviewer name must be one non-empty line of at most 256 bytes")
	}
	if strings.TrimSpace(statement) == "" {
		return nil, fmt.Errorf("pack sign-review: statement is required")
	}
	if _, err := time.Parse(time.RFC3339, reviewedAt); err != nil {
		return nil, fmt.Errorf("pack sign-review: reviewed_at: %w", err)
	}
	fixture := strings.HasPrefix(strings.ToLower(name), "synthetic-reviewer-")
	if p.Metadata.Synthetic != fixture {
		return nil, fmt.Errorf("pack sign-review: synthetic-reviewer-* names sign synthetic packs only, and synthetic packs take only those names")
	}
	sum, err := ContentSHA256(p)
	if err != nil {
		return nil, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pack sign-review: key is not Ed25519")
	}
	sig := ed25519.Sign(priv, ReviewMessage(p.Metadata.ID, sum, name))
	return &ReviewAttestation{Name: name, ReviewedAt: reviewedAt, Statement: statement,
		KeyID: bundle.KeyID(pub), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// KeyLookup returns the trusted public key for a key id, or an error.
type KeyLookup func(keyID string) (ed25519.PublicKey, error)

// VerifyReviewSignatures checks every signed reviewer of rec against keys.
// A signature that does not verify, a key id that is unknown or does not
// match its key, or one key used for two reviewers is an error. With
// require, an unsigned reviewer is an error too. It returns the number of
// verified reviewers. Call CheckReview as well: this checks signatures only.
func VerifyReviewSignatures(rec *ReviewRecord, keys KeyLookup, require bool) (int, error) {
	if rec == nil {
		return 0, fmt.Errorf("pack review: record is required")
	}
	if keys == nil && require {
		return 0, fmt.Errorf("pack review: signatures are required but no reviewer keys were given")
	}
	used := map[string]string{}
	ok := 0
	for _, r := range rec.Reviewers {
		name := strings.TrimSpace(r.Name)
		if r.Signature == "" && r.KeyID == "" {
			if require {
				return ok, fmt.Errorf("pack review: %s is not signed", name)
			}
			continue
		}
		if r.Signature == "" || r.KeyID == "" {
			return ok, fmt.Errorf("pack review: %s needs both key_id and signature", name)
		}
		if !keyIDRE.MatchString(r.KeyID) {
			return ok, fmt.Errorf("pack review: %s key_id %q is not 32 lowercase hex characters", name, r.KeyID)
		}
		if keys == nil {
			return ok, fmt.Errorf("pack review: %s is signed but no reviewer keys were given to check it", name)
		}
		if prev, dup := used[r.KeyID]; dup {
			return ok, fmt.Errorf("pack review: %s and %s are signed with the same key %s", prev, name, r.KeyID)
		}
		used[r.KeyID] = name
		pub, err := keys(r.KeyID)
		if err != nil {
			return ok, fmt.Errorf("pack review: %s key %s: %w", name, r.KeyID, err)
		}
		if bundle.KeyID(pub) != r.KeyID {
			return ok, fmt.Errorf("pack review: %s key file for %s holds key %s", name, r.KeyID, bundle.KeyID(pub))
		}
		sig, err := base64.StdEncoding.DecodeString(r.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return ok, fmt.Errorf("pack review: %s signature is not base64 Ed25519", name)
		}
		if !ed25519.Verify(pub, ReviewMessage(rec.PackID, rec.PackSHA256, name), sig) {
			return ok, fmt.Errorf("pack review: %s signature does not verify for pack %s content %s", name, rec.PackID, rec.PackSHA256)
		}
		ok++
	}
	return ok, nil
}

// ReviewRecord binds reviewer statements to the pack content.
// PackSHA256 is ContentSHA256, which ignores metadata.status and
// metadata.reviewers. Promoting a pack does not invalidate the record.
type ReviewRecord struct {
	PackID     string              `json:"pack_id"`
	PackSHA256 string              `json:"pack_sha256"`
	Reviewers  []ReviewAttestation `json:"reviewers"`
}

// ContentSHA256 hashes the decoded pack with status and reviewers cleared.
// Two files that differ only by promotion metadata have the same hash.
func ContentSHA256(p *Pack) (string, error) {
	if p == nil {
		return "", fmt.Errorf("pack review: pack is nil")
	}
	clone := *p
	clone.Metadata.Status = ""
	clone.Metadata.Reviewers = nil
	clone.FilePath = ""
	clone.SHA256 = ""
	clone.MaxAge = 0
	raw, err := json.Marshal(&clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// ParseReviewRecord decodes a review file. Unknown fields are rejected.
func ParseReviewRecord(data []byte) (*ReviewRecord, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rec ReviewRecord
	if err := dec.Decode(&rec); err != nil {
		return nil, fmt.Errorf("pack review: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("pack review: trailing JSON")
	}
	return &rec, nil
}

// CheckReview reports whether rec is enough to mark p reviewed.
// It does not edit p. Fixture names are accepted only on synthetic packs.
func CheckReview(p *Pack, rec *ReviewRecord) error {
	if p == nil || rec == nil {
		return fmt.Errorf("pack review: pack and record are required")
	}
	if rec.PackID != p.Metadata.ID {
		return fmt.Errorf("pack review: record pack_id %q does not match %q", rec.PackID, p.Metadata.ID)
	}
	sum, err := ContentSHA256(p)
	if err != nil {
		return err
	}
	if rec.PackSHA256 == "" || rec.PackSHA256 != sum {
		return fmt.Errorf("pack review: record pack_sha256 does not match the pack content (status and reviewers are not part of the hash)")
	}
	if len(rec.Reviewers) < 2 {
		return fmt.Errorf("pack review: two distinct reviewers are required")
	}
	seen := map[string]struct{}{}
	for _, r := range rec.Reviewers {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			return fmt.Errorf("pack review: reviewer name is empty")
		}
		if strings.TrimSpace(r.Statement) == "" {
			return fmt.Errorf("pack review: %s has an empty statement", name)
		}
		if _, err := time.Parse(time.RFC3339, r.ReviewedAt); err != nil {
			return fmt.Errorf("pack review: %s reviewed_at: %w", name, err)
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("pack review: duplicate reviewer %q", name)
		}
		seen[key] = struct{}{}
		fixture := strings.HasPrefix(key, "synthetic-reviewer-")
		if p.Metadata.Synthetic && !fixture {
			return fmt.Errorf("pack review: synthetic pack reviewer %q must use a synthetic-reviewer-* name", name)
		}
		if !p.Metadata.Synthetic && fixture {
			return fmt.Errorf("pack review: synthetic-reviewer-* cannot sign a real CVE pack")
		}
	}
	return nil
}

// ReviewerNames returns the record's names in order.
func ReviewerNames(rec *ReviewRecord) []string {
	out := make([]string, 0, len(rec.Reviewers))
	for _, r := range rec.Reviewers {
		out = append(out, strings.TrimSpace(r.Name))
	}
	return out
}

// SameReviewers reports whether the pack YAML lists the same people as the record.
func SameReviewers(p *Pack, rec *ReviewRecord) bool {
	a := map[string]struct{}{}
	for _, r := range p.Metadata.Reviewers {
		a[strings.ToLower(strings.TrimSpace(r.Name))] = struct{}{}
	}
	b := map[string]struct{}{}
	for _, name := range ReviewerNames(rec) {
		b[strings.ToLower(name)] = struct{}{}
	}
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// SortedNames is a stable display of reviewer names.
func SortedNames(names []string) []string {
	out := append([]string{}, names...)
	sort.Strings(out)
	return out
}
