// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/engine"
)

// The advisory below is test-only. It is not a statement about the real
// Ubuntu package, which Ubuntu fixed for CVE-2024-6387 in an earlier revision.
const syntheticAdvisory = `{"facts":[{"asset_id":"lab-ubuntu-sshd","key":"advisory.cve_2024_6387.status",
"purl":"pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.18?arch=arm64&distro=ubuntu-22.04","value":"affected",
"basis":"observed","confidence":"high","observed_at":"2026-11-08T11:00:00Z",
"evidence_id":"e-test-advisory","source":"synthetic test fixture"}]}`

func TestImportHostThenDrill(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	advPath := filepath.Join(dir, "adv.json")
	if err := os.WriteFile(advPath, []byte(syntheticAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	importHost := func(name string, extra ...string) string {
		t.Helper()
		out := filepath.Join(dir, name+".json")
		args := append([]string{
			"import", "host",
			"--input", filepath.Join(root, "examples/collect/lab-ubuntu-sshd.json"),
			"--out", out,
			"--asset-id", "lab-ubuntu-sshd",
			"--kb-version", "demo-2026.11.08",
			"--evaluation-time", "2026-11-08T12:00:00Z",
		}, extra...)
		var stdout, stderr bytes.Buffer
		if err := Execute(args, &stdout, &stderr); err != nil {
			t.Fatalf("%v: %s", err, stderr.String())
		}
		return out
	}
	withAdvisory := func(snap string) string {
		t.Helper()
		out := strings.TrimSuffix(snap, ".json") + "-adv.json"
		var stdout, stderr bytes.Buffer
		if err := Execute([]string{"import", "advisories", "--snapshot", snap, "--advisories", advPath, "--out", out}, &stdout, &stderr); err != nil {
			t.Fatalf("%v: %s", err, stderr.String())
		}
		return out
	}
	drillOne := func(snap string) engine.Verdict {
		t.Helper()
		out := filepath.Join(dir, filepath.Base(snap)+".report.json")
		var stdout, stderr bytes.Buffer
		if err := Execute([]string{
			"drill",
			"--pack", filepath.Join(root, "packs/draft/ecp-cve-2024-6387-openssh.yaml"),
			"--snapshot", snap,
			"--policy", filepath.Join(root, "examples/policy/lab-zones.json"),
			"--out", out,
		}, &stdout, &stderr); err != nil {
			t.Fatalf("%v: %s", err, stderr.String())
		}
		var rep engine.Report
		if err := json.Unmarshal(mustRead(t, out), &rep); err != nil {
			t.Fatal(err)
		}
		if len(rep.Verdicts) != 1 {
			t.Fatalf("%+v", rep.Verdicts)
		}
		v := rep.Verdicts[0]
		if v.State == "not_affected" || v.VEXStatus == "not_affected" {
			t.Fatalf("draft pack and host import produced not_affected: %+v", v)
		}
		return v
	}

	plain := importHost("plain")
	if v := drillOne(plain); v.State != "needs_review" {
		t.Fatalf("deb openssh without an advisory must need review, got %s", v.State)
	}

	noReach := withAdvisory(plain)
	if v := drillOne(noReach); v.State != "exploitable" || !v.ExposureUncertainty {
		t.Fatalf("listening without --reachable-from must fail closed: %s uncertainty=%t", v.State, v.ExposureUncertainty)
	}

	internal := withAdvisory(importHost("internal", "--reachable-from", "internal"))
	if v := drillOne(internal); v.State != "vulnerable_not_exposed" || v.ExposureUncertainty {
		t.Fatalf("internal: %s uncertainty=%t", v.State, v.ExposureUncertainty)
	}

	internet := withAdvisory(importHost("internet", "--reachable-from", "internet"))
	if v := drillOne(internet); v.State != "exploitable" || v.ExposureUncertainty {
		t.Fatalf("internet: %s uncertainty=%t", v.State, v.ExposureUncertainty)
	}
}

func TestImportHostCompleteRefusedWritesNothing(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "host.json")
	out := filepath.Join(dir, "snap.json")
	body := `{"schema":"verdict.collect-host/v1","collector":"collect-host.sh","hostname":"lab-h",
"collected_at":"2026-11-08T11:00:00Z","os":{"id":"ubuntu","version_id":"22.04"},
"packages":[{"manager":"dpkg","name":"bash","version":"5.1-6ubuntu1","purl":"pkg:deb/ubuntu/bash@5.1-6ubuntu1?arch=arm64&distro=ubuntu-22.04"}],
"unparsed":[{"manager":"dpkg","line":"install ok installed\topenssh-server"}],"facts":{},"notes":[]}`
	if err := os.WriteFile(in, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Execute([]string{
		"import", "host", "--input", in, "--out", out, "--asset-id", "lab-h",
		"--kb-version", "demo-2026.11.08", "--evaluation-time", "2026-11-08T12:00:00Z", "--complete",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "inventory cannot be complete") {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("refused import wrote a snapshot: %v", statErr)
	}
}
