// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uddeshya-world/verdict/internal/bundle"
)

// narrowFirst is two OSV records for one CVE in one array file. The narrow
// record (fixed 2.12.0) comes first; the wide one (fixed 2.15.0) covers
// 2.14.1. Reading only the first record per file would miss that.
const narrowFirst = `[
 {"id": "OSV-A-NARROW", "aliases": ["CVE-2021-44228"], "summary": "narrow",
  "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.12.0"}]}]}]},
 {"id": "OSV-B-WIDE", "aliases": ["CVE-2021-44228"], "summary": "wide",
  "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}]}]}
]`

type kbLab struct {
	t        *testing.T
	root     string
	dir      string
	src      string
	priv     string
	pub      string
	kb       string
	snapshot string
	policy   string
}

func newKBLab(t *testing.T) *kbLab {
	t.Helper()
	root := moduleRoot(t)
	dir := t.TempDir()
	l := &kbLab{
		t: t, root: root, dir: dir, src: filepath.Join(dir, "src"),
		priv: filepath.Join(dir, "priv.pem"), pub: filepath.Join(dir, "pub.pem"), kb: filepath.Join(dir, "kb"),
		snapshot: filepath.Join(root, "examples/snapshots/log4shell-lab.json"),
		policy:   filepath.Join(root, "examples/policy/lab-zones.json"),
	}
	if err := os.MkdirAll(filepath.Join(l.src, "osv"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.src, "osv", "conflict.json"), []byte(narrowFirst), 0o644); err != nil {
		t.Fatal(err)
	}
	l.must("bundle", "keygen", "--private-key", l.priv, "--public-key", l.pub)
	return l
}

func (l *kbLab) run(args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	err := Execute(args, &stdout, &stderr)
	return stdout.String() + stderr.String(), err
}

func (l *kbLab) must(args ...string) string {
	l.t.Helper()
	out, err := l.run(args...)
	if err != nil {
		l.t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return out
}

// install builds and installs kb_version ver created at createdAt.
func (l *kbLab) install(ver, createdAt string) string {
	l.t.Helper()
	tarball := filepath.Join(l.dir, ver+".tar")
	l.must("bundle", "build", "--dir", l.src, "--kb-version", ver, "--created-at", createdAt, "--key", l.priv, "--out", tarball)
	l.must("bundle", "install", "--bundle", tarball, "--pubkey", l.pub, "--dir", l.kb)
	return filepath.Join(l.kb, ver)
}

func (l *kbLab) drillKB(ver string, extra ...string) (string, error) {
	out := filepath.Join(l.dir, "r-"+ver+".json")
	args := append([]string{"drill", "--kb", filepath.Join(l.kb, ver), "--pubkey", l.pub, "--cve", "CVE-2021-44228",
		"--snapshot", l.snapshot, "--policy", l.policy, "--out", out}, extra...)
	return l.run(args...)
}

func readReport(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReport(raw); err != nil {
		t.Fatalf("report does not decode strictly: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func states(t *testing.T, path string) map[string]string {
	t.Helper()
	m := readReport(t, path)
	out := map[string]string{}
	for _, v := range m["verdicts"].([]any) {
		vm := v.(map[string]any)
		out[vm["asset_id"].(string)] = vm["state"].(string) + "/" + vm["vex_status"].(string) + "/" + vm["confidence"].(string)
	}
	return out
}

// F8: drill --kb and drill --osv must see the same records.
func TestKBOSVParity(t *testing.T) {
	l := newKBLab(t)
	l.install("t1", "2026-11-08T06:00:00Z")
	if out, err := l.drillKB("t1"); err != nil {
		t.Fatalf("kb drill: %v\n%s", err, out)
	}
	osvOut := filepath.Join(l.dir, "r-osv.json")
	l.must("drill", "--osv", filepath.Join(l.src, "osv", "conflict.json"), "--cve", "CVE-2021-44228",
		"--snapshot", l.snapshot, "--policy", l.policy, "--out", osvOut)
	kb, direct := states(t, filepath.Join(l.dir, "r-t1.json")), states(t, osvOut)
	if len(kb) == 0 || len(kb) != len(direct) {
		t.Fatalf("verdict count kb=%d osv=%d", len(kb), len(direct))
	}
	for id, s := range direct {
		if kb[id] != s {
			t.Errorf("asset %s: --kb %s, --osv %s", id, kb[id], s)
		}
	}
	// 2.14.1 is inside the wide record only; it must not be needs_review.
	if got := kb["lab-log4j-affected"]; got == "" || strings.HasPrefix(got, "needs_review") {
		t.Errorf("lab-log4j-affected under --kb = %s; the wide record after the narrow one was ignored", got)
	}
}

// F9: the report's kb_version comes from the signed bundle, and the report
// names the bundle's key and creation time.
func TestKBVersionOverrideRejectedAndBundleRecorded(t *testing.T) {
	l := newKBLab(t)
	l.install("t1", "2026-11-08T06:00:00Z")
	if out, err := l.drillKB("t1", "--kb-version", "2099.01.01"); err == nil || !strings.Contains(err.Error(), "--kb-version cannot be combined with --kb") {
		t.Fatalf("--kb-version with --kb accepted: %v\n%s", err, out)
	}
	if out, err := l.drillKB("t1"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	m := readReport(t, filepath.Join(l.dir, "r-t1.json"))
	raw, _ := os.ReadFile(l.pub)
	pub, err := bundle.ParsePublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m["kb_version"] != "t1" || m["kb_key_id"] != bundle.KeyID(pub) || m["kb_created_at"] != "2026-11-08T06:00:00Z" {
		t.Fatalf("report kb fields: version=%v key_id=%v created_at=%v", m["kb_version"], m["kb_key_id"], m["kb_created_at"])
	}
	// A drill without --kb does not claim a bundle.
	osvOut := filepath.Join(l.dir, "r-osv.json")
	l.must("drill", "--osv", filepath.Join(l.src, "osv", "conflict.json"), "--snapshot", l.snapshot, "--out", osvOut)
	m = readReport(t, osvOut)
	if _, ok := m["kb_key_id"]; ok {
		t.Fatal("kb_key_id written without --kb")
	}
}

// F10: created_at bounds and the LATEST monotonic floor.
func TestKBFreshnessAndFloor(t *testing.T) {
	l := newKBLab(t)
	orig := nowFunc
	t.Cleanup(func() { nowFunc = orig })
	nowFunc = func() time.Time { return time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC) }
	// Install newest first, then an older one: LATEST must stay on t1.
	l.install("t1", "2026-11-08T06:00:00Z")
	l.install("t0", "2026-11-01T06:00:00Z")
	latest, err := bundle.ReadLatest(l.kb)
	if err != nil || latest == nil || latest.KBVersion != "t1" {
		t.Fatalf("LATEST = %+v, %v; want t1", latest, err)
	}
	if out, err := l.drillKB("t0"); err == nil || !strings.Contains(err.Error(), "--allow-older-kb") {
		t.Fatalf("older install accepted: %v\n%s", err, out)
	}
	if out, err := l.drillKB("t0", "--allow-older-kb"); err != nil || !strings.Contains(out, "--allow-older-kb was given") {
		t.Fatalf("--allow-older-kb: %v\n%s", err, out)
	}
	if out, err := l.drillKB("t1"); err != nil {
		t.Fatalf("current install: %v\n%s", err, out)
	}
	// evaluation_time is 2026-11-08T12:00:00Z: t1 is 6h old, t0 is 7d6h old.
	if out, err := l.drillKB("t1", "--max-kb-age", "1d"); err != nil {
		t.Fatalf("fresh bundle refused: %v\n%s", err, out)
	}
	if out, err := l.drillKB("t0", "--allow-older-kb", "--max-kb-age", "7d"); err == nil || !strings.Contains(err.Error(), "--max-kb-age") {
		t.Fatalf("stale bundle accepted: %v\n%s", err, out)
	}
	if out, err := l.drillKB("t1", "--max-kb-age", "5h"); err == nil {
		t.Fatalf("bundle older than 5h accepted: %s", out)
	}
	if out, err := l.drillKB("t1", "--max-kb-age", "-1h"); err == nil {
		t.Fatalf("negative age accepted: %s", out)
	}
	// A bundle created after the evaluation time is allowed (older snapshot,
	// newer KB) with a stderr note, and the report keeps both timestamps.
	l.install("t2", "2026-11-09T06:00:00Z")
	out, err := l.drillKB("t2")
	if err != nil || !strings.Contains(out, "kb is newer than the snapshot") {
		t.Fatalf("newer bundle: %v\n%s", err, out)
	}
	m := readReport(t, filepath.Join(l.dir, "r-t2.json"))
	if m["kb_created_at"] != "2026-11-09T06:00:00Z" || !strings.HasPrefix(fmt.Sprint(m["evaluation_time"]), "2026-11-08T12:00:00") {
		t.Fatalf("report times: kb_created_at=%v evaluation_time=%v", m["kb_created_at"], m["evaluation_time"])
	}
	// --max-kb-age still compares against evaluation_time: t2 is 18h after it.
	if out, err := l.drillKB("t2", "--max-kb-age", "1h"); err != nil {
		t.Fatalf("newer bundle failed max age: %v\n%s", err, out)
	}
	// A bundle created after the wall clock plus 5 minutes is refused.
	nowFunc = func() time.Time { return time.Date(2026, 11, 9, 5, 54, 59, 0, time.UTC) }
	if out, err := l.drillKB("t2"); err == nil || !strings.Contains(err.Error(), "in the future") {
		t.Fatalf("future bundle accepted: %v\n%s", err, out)
	}
	nowFunc = func() time.Time { return time.Date(2026, 11, 9, 5, 55, 0, 0, time.UTC) }
	if out, err := l.drillKB("t2"); err != nil {
		t.Fatalf("bundle within skew refused: %v\n%s", err, out)
	}
	// t2 is now the floor, so t1 needs the override too.
	if out, err := l.drillKB("t1", "--evaluation-time", "2026-11-10T00:00:00Z"); err == nil {
		t.Fatalf("t1 accepted after t2 install: %s", out)
	}
	// The freshness flags need --kb.
	if out, err := l.run("drill", "--osv", filepath.Join(l.src, "osv", "conflict.json"), "--snapshot", l.snapshot, "--max-kb-age", "1d"); err == nil {
		t.Fatalf("--max-kb-age without --kb accepted: %s", out)
	}
}

func TestKBWithoutLatestStillRuns(t *testing.T) {
	l := newKBLab(t)
	l.install("t1", "2026-11-08T06:00:00Z")
	if err := os.Remove(filepath.Join(l.kb, bundle.LatestName)); err != nil {
		t.Fatal(err)
	}
	out, err := l.drillKB("t1")
	if err != nil || !strings.Contains(out, "computed from signed bundles") {
		t.Fatalf("%v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(l.kb, bundle.LatestName), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := l.drillKB("t1"); err == nil {
		t.Fatalf("malformed LATEST accepted: %s", out)
	}
}

func TestParseAge(t *testing.T) {
	for in, want := range map[string]time.Duration{"30d": 30 * 24 * time.Hour, "12h": 12 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := parseAge(in); err != nil || got != want {
			t.Errorf("parseAge(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0d", "-1d", "xd", "0s", "-5m", "1y"} {
		if _, err := parseAge(bad); err == nil {
			t.Errorf("parseAge(%q) accepted", bad)
		}
	}
}

// A37: the floor comes from signed bundles, not from LATEST alone.
func TestKBFloorFromSignedBundles(t *testing.T) {
	l := newKBLab(t)
	orig := nowFunc
	t.Cleanup(func() { nowFunc = orig })
	nowFunc = func() time.Time { return time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC) }
	l.install("t0", "2026-11-01T06:00:00Z")
	l.install("t1", "2026-11-08T06:00:00Z")
	latestPath := filepath.Join(l.kb, bundle.LatestName)

	// Lowered LATEST (names t0) is ignored: t0 is still refused.
	if err := os.WriteFile(latestPath, []byte(`{"kb_version":"t0","created_at":"2026-11-01T06:00:00Z"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := l.drillKB("t0")
	if err == nil || !strings.Contains(err.Error(), "signed floor t1") {
		t.Fatalf("older kb accepted with lowered LATEST: %v\n%s", err, out)
	}
	// A forged-low created_at for the true newest version does not help either.
	if err := os.WriteFile(latestPath, []byte(`{"kb_version":"t1","created_at":"2026-10-01T00:00:00Z"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := l.drillKB("t0"); err == nil {
		t.Fatalf("older kb accepted with forged LATEST time: %s", out)
	}
	// Deleted LATEST still enforces the floor.
	if err := os.Remove(latestPath); err != nil {
		t.Fatal(err)
	}
	if out, err := l.drillKB("t0"); err == nil {
		t.Fatalf("older kb accepted with LATEST deleted: %s", out)
	}
	if out, err := l.drillKB("t1"); err != nil || !strings.Contains(out, "computed from signed bundles") {
		t.Fatalf("newest with LATEST deleted: %v\n%s", err, out)
	}
	if out, err := l.drillKB("t0", "--allow-older-kb"); err != nil {
		t.Fatalf("--allow-older-kb: %v\n%s", err, out)
	}
}

func TestKBTamperedNewerBundleNotCounted(t *testing.T) {
	l := newKBLab(t)
	orig := nowFunc
	t.Cleanup(func() { nowFunc = orig })
	nowFunc = func() time.Time { return time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC) }
	l.install("t0", "2026-11-01T06:00:00Z")
	t1 := l.install("t1", "2026-11-08T06:00:00Z")
	// Flip a byte in the newer bundle: it no longer verifies, so it cannot
	// raise the floor, and t0 (now the newest verified) runs with a note.
	// LATEST is removed so the unsigned hint is not what is being tested.
	tarPath := filepath.Join(t1, "bundle.tar")
	raw, err := os.ReadFile(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(tarPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(l.kb, bundle.LatestName)); err != nil {
		t.Fatal(err)
	}
	out, err := l.drillKB("t0")
	if err != nil || !strings.Contains(out, "floor scan: t1 not counted") {
		t.Fatalf("tampered newer bundle: %v\n%s", err, out)
	}
	// A validly signed bundle copied under a different directory name is not counted.
	raw2, _ := os.ReadFile(filepath.Join(l.kb, "t0", "bundle.tar"))
	if err := os.MkdirAll(filepath.Join(l.kb, "t9"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.kb, "t9", "bundle.tar"), raw2, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := l.drillKB("t0"); err != nil || !strings.Contains(out, "t9 not counted: signed as kb_version t0") {
		t.Fatalf("misnamed dir: %v\n%s", err, out)
	}
}

func TestKBRequireFloor(t *testing.T) {
	l := newKBLab(t)
	orig := nowFunc
	t.Cleanup(func() { nowFunc = orig })
	nowFunc = func() time.Time { return time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC) }
	l.install("t1", "2026-11-08T06:00:00Z")
	if out, err := l.drillKB("t1", "--require-floor"); err == nil || !strings.Contains(err.Error(), "--require-floor") {
		t.Fatalf("sole bundle accepted with --require-floor: %v\n%s", err, out)
	}
	if out, err := l.drillKB("t1"); err != nil {
		t.Fatalf("without --require-floor: %v\n%s", err, out)
	}
	l.install("t0", "2026-11-01T06:00:00Z")
	if out, err := l.drillKB("t1", "--require-floor"); err != nil {
		t.Fatalf("two bundles with --require-floor: %v\n%s", err, out)
	}
	if out, err := l.run("drill", "--osv", filepath.Join(l.src, "osv", "conflict.json"), "--snapshot", l.snapshot, "--require-floor"); err == nil {
		t.Fatalf("--require-floor without --kb accepted: %s", out)
	}
}
