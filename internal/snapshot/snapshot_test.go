// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package snapshot

import (
	"strings"
	"testing"
)

const dupDoc = `{"kb_version":"k","evaluation_time":"2026-11-08T12:00:00Z","evidence_trust":"caller_asserted","assets":[{"id":"a","name":"a","kind":"host",
"inventory":{"complete":true,"observed_at":"2026-11-08T11:00:00Z","basis":"observed","confidence":"high","evidence_id":"e-inv",
"packages":[{"purl":"pkg:deb/ubuntu/openssh-server@1:8.9p1-3?arch=amd64&distro=ubuntu-22.04","version":"1:8.9p1-3"}]},
"facts":[
{"key":"advisory.x","value":"fixed","basis":"observed","confidence":"high","observed_at":"2026-11-08T11:00:00Z","evidence_id":"e1","source":"s","purl":"PURL_A"},
{"key":"advisory.x","value":"affected","basis":"observed","confidence":"high","observed_at":"2026-11-08T11:00:00Z","evidence_id":"e2","source":"s","purl":"PURL_B"}]}]}`

func TestAdvisorySpellingsLoadAndExactDuplicatesDoNot(t *testing.T) {
	p := "pkg:deb/ubuntu/openssh-server@1:8.9p1-3?arch=amd64&distro=ubuntu-22.04"
	spelled := "pkg:deb/ubuntu/openssh-server@1%3A8.9p1-3?distro=ubuntu-22.04&arch=amd64"
	doc := strings.NewReplacer("PURL_A", spelled, "PURL_B", p).Replace(dupDoc)
	if _, err := Load([]byte(doc)); err != nil {
		t.Fatalf("spelling variants are left for the engine to treat as a conflict: %v", err)
	}
	doc = strings.NewReplacer("PURL_A", p, "PURL_B", p).Replace(dupDoc)
	if _, err := Load([]byte(doc)); err == nil || !strings.Contains(err.Error(), "duplicate fact") {
		t.Fatalf("byte-identical duplicate must be rejected: %v", err)
	}
}
