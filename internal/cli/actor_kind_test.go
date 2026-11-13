// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/engine"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func wantExit2(t *testing.T, sub string, args ...string) {
	t.Helper()
	o, err := runCLI(args...)
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 2 {
		t.Fatalf("want exit 2 for %v, got %v\n%s", args, err, o)
	}
	if !strings.Contains(o+err.Error(), sub) {
		t.Fatalf("want %q in error, got %v\n%s", sub, err, o)
	}
}

// An agent cannot enter an observed fact or exposure, and an unknown actor
// kind is refused. Nothing is written for a refused edit.
func TestActorKindRefusals(t *testing.T) {
	dir := t.TempDir()
	in, id := sshBase(t, dir)
	out := filepath.Join(dir, "out.json")
	ev := filepath.Join(dir, "ev.txt")
	os.WriteFile(ev, []byte("ldd --version: musl libc\n"), 0o644)
	T := "2026-11-08T11:00:00Z"
	fact := []string{"snapshot", "set-fact", "--snapshot", in, "--out", out, "--asset", id, "--key", "libc.family", "--value", "musl"}
	exp := []string{"snapshot", "set-exposure", "--snapshot", in, "--out", out, "--asset", id, "--port", "8022", "--proto", "tcp", "--reachable-from", "internal"}

	wantExit2(t, "actor_kind agent cannot enter basis observed", append(fact, "--actor-kind", "agent", "--basis", "observed", "--confidence", "high", "--evidence", ev, "--observed-at", T)...)
	wantExit2(t, "actor_kind agent cannot enter basis observed", append(fact, "--actor-kind", "agent", "--basis", "observed", "--evidence", ev, "--observed-at", T)...)
	wantExit2(t, "requires basis observed", append(fact, "--actor-kind", "agent", "--confidence", "high")...)
	wantExit2(t, "actor_kind agent cannot enter basis observed", append(exp, "--actor-kind", "agent", "--basis", "observed", "--confidence", "high", "--evidence", ev, "--observed-at", T)...)
	wantExit2(t, "actor_kind must be human or agent", append(fact, "--actor-kind", "robot")...)
	wantExit2(t, "actor_kind must be human or agent", append(exp, "--actor-kind", "")...)
	if _, err := os.Stat(out); err == nil {
		t.Fatal("output written for a refused edit")
	}

	write := func(v any) string {
		b, _ := json.Marshal(v)
		p := filepath.Join(dir, "edits.json")
		os.WriteFile(p, b, 0o644)
		return p
	}
	apply := func(f string, extra ...string) []string {
		return append([]string{"snapshot", "apply", "--snapshot", in, "--out", out, "--file", f}, extra...)
	}
	att := map[string]any{"op": "set_fact", "asset": id, "key": "libc.family", "value": "musl"}
	human := map[string]any{"op": "set_fact", "asset": id, "key": "x.y", "value": "v", "actor_kind": "human"}
	obsAgent := map[string]any{"op": "set_fact", "asset": id, "key": "libc.family", "value": "musl", "actor_kind": "agent",
		"basis": "observed", "confidence": "high", "observed_at": T, "evidence_file": "ev.txt"}
	obs := map[string]any{"op": "set_fact", "asset": id, "key": "libc.family", "value": "musl",
		"basis": "observed", "confidence": "high", "observed_at": T, "evidence_file": "ev.txt"}
	wantExit2(t, "actor_kind human in a batch applied with --actor-kind agent", apply(write(map[string]any{"edits": []any{att, human}}), "--actor-kind", "agent")...)
	wantExit2(t, "actor_kind agent cannot enter basis observed", apply(write(map[string]any{"edits": []any{obsAgent}}))...)
	wantExit2(t, "actor_kind agent cannot enter basis observed", apply(write(map[string]any{"edits": []any{obs}}), "--actor-kind", "agent")...)
	wantExit2(t, "actor_kind must be human or agent", apply(write(map[string]any{"edits": []any{map[string]any{"op": "set_fact", "asset": id, "key": "a", "value": "b", "actor_kind": "robot"}}}))...)
	wantExit2(t, "--actor-kind: actor_kind must be human or agent", apply(write(map[string]any{"edits": []any{att}}), "--actor-kind", "bot")...)
	if _, err := os.Stat(out); err == nil {
		t.Fatal("output written for a refused batch")
	}
}

// Every edit record names its actor; the default is human.
func TestActorKindRecorded(t *testing.T) {
	dir := t.TempDir()
	in, id := sshBase(t, dir)
	out := filepath.Join(dir, "out.json")
	base := []string{"snapshot", "set-fact", "--snapshot", in, "--out", out, "--asset", id, "--key", "libc.family", "--value", "musl"}
	if o, err := runCLI(base...); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	if e := loadOut(t, out).Assets[0].Edits; len(e) != 1 || e[0].ActorKind != "human" {
		t.Fatalf("%+v", e)
	}
	if o, err := runCLI(append(base, "--actor-kind", "agent", "--confidence", "low")...); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	a := loadOut(t, out).Assets[0]
	if len(a.Edits) != 1 || a.Edits[0].ActorKind != "agent" || a.Facts[len(a.Facts)-1].Basis != "attested" {
		t.Fatalf("%+v", a.Edits)
	}
	// apply: entries without actor_kind take the flag; an explicit agent
	// entry stays agent under the human default.
	f := filepath.Join(dir, "edits.json")
	b, _ := json.Marshal(map[string]any{"edits": []any{
		map[string]any{"op": "set_fact", "asset": id, "key": "a.b", "value": "1"},
		map[string]any{"op": "set_fact", "asset": id, "key": "c.d", "value": "2", "actor_kind": "agent"},
	}})
	os.WriteFile(f, b, 0o644)
	if o, err := runCLI("snapshot", "apply", "--snapshot", in, "--out", out, "--file", f); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	if e := loadOut(t, out).Assets[0].Edits; len(e) != 2 || e[0].ActorKind != "human" || e[1].ActorKind != "agent" {
		t.Fatalf("%+v", e)
	}
	if o, err := runCLI("snapshot", "apply", "--snapshot", in, "--out", out, "--file", f, "--actor-kind", "agent"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	if e := loadOut(t, out).Assets[0].Edits; len(e) != 2 || e[0].ActorKind != "agent" || e[1].ActorKind != "agent" {
		t.Fatalf("%+v", e)
	}
}

// A snapshot hand-edited so an agent's record sits behind an observed, high,
// evidenced, fresh fact still cannot reach not_affected on the reviewed bar.
// The same fact entered by a human does (control), and a human re-entry after
// the agent restores it: the latest record decides.
func TestAgentEditedObservedFactNeverClears(t *testing.T) {
	dir := t.TempDir()
	in, id := sshBase(t, dir)
	ev := filepath.Join(dir, "ev.txt")
	os.WriteFile(ev, []byte("ldd --version: musl libc\n"), 0o644)
	human := filepath.Join(dir, "human.json")
	if o, err := runCLI("snapshot", "set-fact", "--snapshot", in, "--out", human, "--asset", id, "--key", "libc.family", "--value", "musl",
		"--basis", "observed", "--confidence", "high", "--evidence", ev, "--observed-at", "2026-11-08T11:00:00Z"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	if v := reviewedOpenSSH(t, human); v.State != "not_affected" {
		t.Fatalf("control: human observed fact did not clear: %s", v.State)
	}
	s := loadOut(t, human)
	s.Assets[0].Edits[0].ActorKind = snapshot.ActorAgent
	forged := filepath.Join(dir, "forged.json")
	body, _ := json.Marshal(s)
	os.WriteFile(forged, body, 0o644)
	v := reviewedOpenSSH(t, forged)
	if v.State == "not_affected" || v.VEXStatus == "not_affected" {
		t.Fatalf("agent-edited observed fact reached not_affected: %+v", v)
	}
	var leafHit, hintHit bool
	for _, l := range v.Leaves {
		if l.Reason == engine.ReasonAgentEditNotObserved {
			leafHit = true
			if l.Observed {
				t.Fatalf("agent leaf observed: %+v", l)
			}
		}
	}
	for _, h := range v.Hints {
		if h.Reason == engine.ReasonAgentEditNotObserved && strings.Contains(h.Hint, "actor_kind agent") {
			hintHit = true
		}
	}
	if !leafHit || !hintHit {
		t.Fatalf("no agent_edit_not_observed leaf/hint: %+v", v)
	}
	// A later human record for the same fact is the latest edit.
	s.Assets[0].Edits = append(s.Assets[0].Edits, s.Assets[0].Edits[0])
	s.Assets[0].Edits[1].ActorKind = snapshot.ActorHuman
	s.Assets[0].Edits[1].OldValue, s.Assets[0].Edits[1].OldBasis, s.Assets[0].Edits[1].Replaced = "musl", "observed", true
	body, _ = json.Marshal(s)
	os.WriteFile(forged, body, 0o644)
	if v := reviewedOpenSSH(t, forged); v.State != "not_affected" {
		t.Fatalf("human re-entry after agent: %s", v.State)
	}
	// The report validates against the schema and the reason catalog.
	s.Assets[0].Edits = s.Assets[0].Edits[:1]
	body, _ = json.Marshal(s)
	os.WriteFile(forged, body, 0o644)
	out := filepath.Join(dir, "rep.json")
	root := moduleRoot(t)
	if o, err := runCLI("drill", "--pack", filepath.Join(root, "packs/draft/ecp-cve-2024-6387-openssh.yaml"), "--snapshot", forged, "--out", out); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	if o, err := runCLI("report", "validate", out); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
}
