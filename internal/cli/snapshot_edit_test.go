// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uddeshya-world/verdict/internal/engine"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/policy"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func runCLI(args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	err := Execute(args, &stdout, &stderr)
	return stdout.String() + stderr.String(), err
}

// sshBase writes the regreSSHion lab asset with its libc.family fact removed,
// so the tests can add it back with chosen quality. Returns path and asset id.
func sshBase(t *testing.T, dir string) (string, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), "examples/snapshots/regresshion-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	a := s.Assets[0]
	var facts []snapshot.Fact
	for _, f := range a.Facts {
		if f.Key != "libc.family" {
			facts = append(facts, f)
		}
	}
	a.Facts = facts
	s.Assets = []snapshot.Asset{a}
	body, _ := json.Marshal(s)
	path := filepath.Join(dir, "base.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, a.ID
}

func loadOut(t *testing.T, path string) *snapshot.Snapshot {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.Load(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSetFactRules(t *testing.T) {
	dir := t.TempDir()
	in, id := sshBase(t, dir)
	out := filepath.Join(dir, "out.json")
	evFile := filepath.Join(dir, "ev.txt")
	os.WriteFile(evFile, []byte("sshd -T output\n"), 0o644)
	sum := sha256.Sum256([]byte("sshd -T output\n"))
	wantID := "sha256:" + hex.EncodeToString(sum[:])
	T := "2026-11-08T11:30:00Z"
	base := []string{"snapshot", "set-fact", "--snapshot", in, "--out", out, "--asset", id, "--key", "libc.family", "--value", "musl"}
	refuse := func(sub string, extra ...string) {
		t.Helper()
		os.Remove(out)
		o, err := runCLI(append(append([]string{}, base...), extra...)...)
		if err == nil || !strings.Contains(o+err.Error(), sub) {
			t.Fatalf("want refusal containing %q, got err=%v\n%s", sub, err, o)
		}
		if _, serr := os.Stat(out); serr == nil {
			t.Fatal("output written for a refused edit")
		}
	}
	refuse("requires an evidence file", "--basis", "observed", "--observed-at", T)
	refuse("requires basis observed", "--confidence", "high")
	refuse("requires basis observed", "--confidence", "high", "--evidence", evFile)
	refuse("requires observed_at", "--basis", "observed", "--evidence", evFile)
	refuse("not in the snapshot", "--asset", "nope")
	refuse("not an inventory package", "--purl", "pkg:deb/ubuntu/curl@1")
	refuse("fact key", "--key", "bad key")
	refuse("evidence", "--basis", "observed", "--observed-at", T, "--evidence", filepath.Join(dir, "missing"))
	refuse("one of", "--value", "uclibc") // collector value rule for libc.family

	if o, err := runCLI(base...); err != nil {
		t.Fatalf("attested default: %v\n%s", err, o)
	}
	f := loadOut(t, out).Assets[0].Facts
	if g := f[len(f)-1]; g.Basis != "attested" || g.Confidence != "medium" || g.Key != "libc.family" {
		t.Fatalf("%+v", g)
	}
	// Overwrite needs --replace, and --max-snapshot-bytes is honored.
	in2 := out
	out2 := filepath.Join(dir, "out2.json")
	args := []string{"snapshot", "set-fact", "--snapshot", in2, "--out", out2, "--asset", id, "--key", "libc.family", "--value", "glibc"}
	if o, err := runCLI(args...); err == nil || !strings.Contains(o+err.Error(), "pass replace") {
		t.Fatalf("silent overwrite: %v %s", err, o)
	}
	if o, err := runCLI(append(args, "--replace", "--basis", "observed", "--confidence", "high", "--observed-at", T, "--evidence", evFile)...); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	for _, g := range loadOut(t, out2).Assets[0].Facts {
		if g.Key == "libc.family" && (g.Value != "glibc" || g.EvidenceID != wantID || g.Confidence != "high" || g.Basis != "observed") {
			t.Fatalf("%+v", g)
		}
	}
	if _, err := runCLI(append(args, "--replace", "--max-snapshot-bytes", "50")...); err == nil {
		t.Fatal("cap not honored")
	}
	// Purl accepted when it is an inventory package.
	if o, err := runCLI("snapshot", "set-fact", "--snapshot", in, "--out", out, "--asset", id, "--key", "advisory.x", "--value", "fixed", "--purl", "pkg:generic/openssh@9.6p1"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
}

func TestSetExposureCLI(t *testing.T) {
	dir := t.TempDir()
	in, id := sshBase(t, dir)
	out := filepath.Join(dir, "out.json")
	// regresshion-lab asset already exposes 22/tcp to some zone(s): narrowing is refused.
	cur := loadOut(t, in).Assets[0].Exposure[0]
	if cur.Port != 22 {
		t.Fatalf("fixture changed: %+v", cur)
	}
	o, err := runCLI("snapshot", "set-exposure", "--snapshot", in, "--out", out, "--asset", id, "--port", "22", "--proto", "tcp", "--reachable-from", "zz-new")
	if err == nil || !strings.Contains(o+err.Error(), "would drop") {
		t.Fatalf("narrowing allowed: %v %s", err, o)
	}
	zones := strings.Join(append(append([]string{}, cur.ReachableFrom...), "zz-new"), ",")
	if o, err := runCLI("snapshot", "set-exposure", "--snapshot", in, "--out", out, "--asset", id, "--port", "22", "--proto", "tcp", "--reachable-from", zones); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	if o, err := runCLI("snapshot", "set-exposure", "--snapshot", in, "--out", out, "--asset", id, "--port", "22", "--proto", "tcp", "--reachable-from", "zz-new", "--replace"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	if z := loadOut(t, out).Assets[0].Exposure[0].ReachableFrom; len(z) != 1 || z[0] != "zz-new" {
		t.Fatalf("%v", z)
	}
	if _, err := runCLI("snapshot", "set-exposure", "--snapshot", in, "--out", out, "--asset", id, "--port", "80", "--proto", "tcp", "--reachable-from", "internet", "--basis", "observed"); err == nil {
		t.Fatal("observed exposure without evidence accepted")
	}
}

func TestSnapshotApplyAtomic(t *testing.T) {
	dir := t.TempDir()
	in, id := sshBase(t, dir)
	out := filepath.Join(dir, "out.json")
	os.WriteFile(filepath.Join(dir, "ev.txt"), []byte("proof"), 0o644)
	write := func(v any) string {
		b, _ := json.Marshal(v)
		p := filepath.Join(dir, "edits.json")
		os.WriteFile(p, b, 0o644)
		return p
	}
	good := map[string]any{"op": "set_fact", "asset": id, "key": "libc.family", "value": "glibc",
		"basis": "observed", "confidence": "high", "observed_at": "2026-11-08T11:00:00Z", "evidence_file": "ev.txt"}
	bad := map[string]any{"op": "set_fact", "asset": id, "key": "x.y", "value": "v", "confidence": "high"}
	exp := map[string]any{"op": "set_exposure", "asset": id, "port": 8022, "proto": "tcp", "reachable_from": []string{"internal"}}

	f := write(map[string]any{"edits": []any{good, exp, bad}})
	o, err := runCLI("snapshot", "apply", "--snapshot", in, "--out", out, "--file", f)
	if err == nil || !strings.Contains(o+err.Error(), "edit 3") {
		t.Fatalf("bad batch accepted: %v %s", err, o)
	}
	if _, serr := os.Stat(out); serr == nil {
		t.Fatal("partial output written")
	}
	f = write(map[string]any{"edits": []any{good, exp}})
	if o, err := runCLI("snapshot", "apply", "--snapshot", in, "--out", out, "--file", f); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	a := loadOut(t, out).Assets[0]
	if len(a.Exposure) != 2 || a.Facts[len(a.Facts)-1].EvidenceID == "" || !strings.HasPrefix(a.Facts[len(a.Facts)-1].EvidenceID, "sha256:") {
		t.Fatalf("%+v", a)
	}
	// Unknown fields (including a smuggled evidence_id) are refused.
	f = write(map[string]any{"edits": []any{map[string]any{"op": "set_fact", "asset": id, "key": "a", "value": "b", "evidence_id": "sha256:aa"}}})
	if _, err := runCLI("snapshot", "apply", "--snapshot", in, "--out", out, "--file", f); err == nil {
		t.Fatal("evidence_id accepted in an edits file")
	}
}

// reviewedOpenSSH evaluates the openssh pack with the reviewed bar applied in
// memory (the pack file is unchanged), as internal/bench does.
func reviewedOpenSSH(t *testing.T, snapPath string) engine.Verdict {
	t.Helper()
	root := moduleRoot(t)
	pp := filepath.Join(root, "packs/draft/ecp-cve-2024-6387-openssh.yaml")
	pd, err := os.ReadFile(pp)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pack.Load(pp, pd)
	if err != nil {
		t.Fatal(err)
	}
	p.Metadata.Status = "reviewed"
	p.Metadata.Reviewers = []pack.Person{{Name: "synthetic-reviewer-alpha"}, {Name: "synthetic-reviewer-beta"}}
	pol, err := os.ReadFile(filepath.Join(root, "examples/policy/lab-zones.json"))
	if err != nil {
		t.Fatal(err)
	}
	pl, err := policy.Load(pol)
	if err != nil {
		t.Fatal(err)
	}
	s := loadOut(t, snapPath)
	at, _ := time.Parse(time.RFC3339, s.EvaluationTime)
	rep, err := engine.Evaluate(engine.Input{Pack: p, Policy: pl, Snapshot: s, EvaluationTime: at, KBVersion: s.KBVersion})
	if err != nil {
		t.Fatal(err)
	}
	return rep.Verdicts[0]
}

// An operator-entered libc.family=musl clears the glibc precondition only when
// it is observed, evidenced, high, and fresh. Attested never does.
func TestSetFactReviewedBar(t *testing.T) {
	dir := t.TempDir()
	in, id := sshBase(t, dir)
	ev := filepath.Join(dir, "ev.txt")
	os.WriteFile(ev, []byte("ldd --version: musl libc\n"), 0o644)
	run := func(name string, extra ...string) engine.Verdict {
		t.Helper()
		out := filepath.Join(dir, name+".json")
		args := append([]string{"snapshot", "set-fact", "--snapshot", in, "--out", out, "--asset", id, "--key", "libc.family", "--value", "musl"}, extra...)
		if o, err := runCLI(args...); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, o)
		}
		return reviewedOpenSSH(t, out)
	}
	notNA := func(v engine.Verdict) bool { return v.State == "not_affected" || v.VEXStatus == "not_affected" }

	if v := run("att-med"); notNA(v) {
		t.Fatalf("attested/medium musl reached not_affected: %+v", v)
	}
	if v := run("att-low", "--confidence", "low"); notNA(v) {
		t.Fatalf("attested/low musl reached not_affected: %+v", v)
	}
	if v := run("obs-medium", "--basis", "observed", "--evidence", ev, "--observed-at", "2026-11-08T11:00:00Z"); notNA(v) {
		t.Fatalf("observed/medium musl reached not_affected: %+v", v)
	}
	if v := run("obs-stale", "--basis", "observed", "--confidence", "high", "--evidence", ev, "--observed-at", "2026-10-01T00:00:00Z"); notNA(v) {
		t.Fatalf("stale observed musl reached not_affected: %+v", v)
	}
	// Control: the bar is reachable by this path.
	if v := run("obs-high", "--basis", "observed", "--confidence", "high", "--evidence", ev, "--observed-at", "2026-11-08T11:00:00Z"); !notNA(v) {
		t.Fatalf("observed+evidence+high+fresh musl did not reach not_affected (control): %+v", v)
	}
}

// An observed, high musl fact entered by an operator reaches not_affected on
// the reviewed bar; the report and OpenVEX must say it is operator-edited.
func TestDrillMarksOperatorEdits(t *testing.T) {
	dir := t.TempDir()
	in, id := sshBase(t, dir)
	ev := filepath.Join(dir, "ev.txt")
	os.WriteFile(ev, []byte("ldd --version: musl libc\n"), 0o644)
	edited := filepath.Join(dir, "edited.json")
	if o, err := runCLI("snapshot", "set-fact", "--snapshot", in, "--out", edited, "--asset", id, "--key", "libc.family", "--value", "musl",
		"--basis", "observed", "--confidence", "high", "--evidence", ev, "--observed-at", "2026-11-08T11:00:00Z", "--source", "ticket 42"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	a := loadOut(t, edited).Assets[0]
	if len(a.Edits) != 1 || a.Edits[0].Source != "ticket 42" || !strings.HasPrefix(a.Edits[0].EvidenceID, "sha256:") {
		t.Fatalf("%+v", a.Edits)
	}
	v := reviewedOpenSSH(t, edited)
	if v.State != "not_affected" || v.OperatorEdits != 1 {
		t.Fatalf("state=%s edits=%d", v.State, v.OperatorEdits)
	}
	marked := 0
	for _, l := range v.Leaves {
		if l.OperatorEdited {
			marked++
		}
	}
	if marked == 0 || !strings.Contains(v.ImpactStatement, "relies on operator-edited evidence") {
		t.Fatalf("marked=%d impact=%q", marked, v.ImpactStatement)
	}
	// The same drill on the unedited snapshot carries no marks.
	plain := reviewedOpenSSH(t, in)
	if plain.OperatorEdits != 0 || strings.Contains(plain.ImpactStatement, "operator-edited") {
		t.Fatalf("unedited asset marked: %+v", plain)
	}
	for _, l := range plain.Leaves {
		if l.OperatorEdited {
			t.Fatal("unedited leaf marked")
		}
	}
	// The CLI stderr line and the JSON field.
	out := filepath.Join(dir, "rep.json")
	root := moduleRoot(t)
	o, err := runCLI("drill", "--pack", filepath.Join(root, "packs/draft/ecp-cve-2024-6387-openssh.yaml"), "--snapshot", edited, "--out", out)
	if err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	if !strings.Contains(o, "(operator-edited)") {
		t.Fatalf("stderr line missing mark:\n%s", o)
	}
	raw, _ := os.ReadFile(out)
	if !strings.Contains(string(raw), `"operator_edits": 1`) || !strings.Contains(string(raw), `"operator_edited": true`) {
		t.Fatalf("report lacks marks: %s", raw)
	}
	o, err = runCLI("drill", "--pack", filepath.Join(root, "packs/draft/ecp-cve-2024-6387-openssh.yaml"), "--snapshot", in, "--out", out)
	if err != nil || strings.Contains(o, "operator-edited") {
		t.Fatalf("%v\n%s", err, o)
	}
	raw, _ = os.ReadFile(out)
	if strings.Contains(string(raw), "operator_edit") {
		t.Fatal("unedited report carries operator_edit fields")
	}
}
