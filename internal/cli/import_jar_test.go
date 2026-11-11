// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/engine"
)

func writeLog4jJar(t *testing.T, path string, withJndi bool) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	files := map[string]string{
		"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n",
		"org/apache/logging/log4j/core/Logger.class":                        "\xca\xfe\xba\xbe",
	}
	if withJndi {
		files["org/apache/logging/log4j/core/lookup/JndiLookup.class"] = "\xca\xfe\xba\xbe"
	}
	for _, name := range []string{
		"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
		"org/apache/logging/log4j/core/Logger.class",
		"org/apache/logging/log4j/core/lookup/JndiLookup.class",
	} {
		body, ok := files[name]
		if !ok {
			continue
		}
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func importAndDrill(t *testing.T, root, dir, id string, withJndi bool, extra ...string) engine.Verdict {
	t.Helper()
	jar := filepath.Join(dir, id+".jar")
	writeLog4jJar(t, jar, withJndi)
	snapPath := filepath.Join(dir, id+".json")
	var stdout, stderr bytes.Buffer
	args := append([]string{
		"import", "jar",
		"--input", jar, "--out", snapPath,
		"--asset-id", id, "--asset-name", id, "--zone", "internet",
		"--kb-version", "demo-2026.11.08",
		"--evaluation-time", "2026-11-08T12:00:00Z",
		"--observed-at", "2026-11-08T11:00:00Z",
	}, extra...)
	if err := Execute(args, &stdout, &stderr); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "runtime.jdk9_or_newer omitted") {
		t.Fatalf("stderr: %s", stderr.String())
	}
	reportPath := filepath.Join(dir, id+"-report.json")
	stdout.Reset()
	stderr.Reset()
	if err := Execute([]string{
		"drill",
		"--pack", filepath.Join(root, "packs/draft/ecp-cve-2021-44228-log4j.yaml"),
		"--snapshot", snapPath,
		"--policy", filepath.Join(root, "examples/policy/lab-zones.json"),
		"--out", reportPath,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var rep engine.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Verdicts) != 1 {
		t.Fatalf("%+v", rep.Verdicts)
	}
	return rep.Verdicts[0]
}

func TestImportJarThenDrillLog4j(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	vuln := importAndDrill(t, root, dir, "jar-log4j-vulnerable", true)
	if vuln.State == "not_affected" || vuln.VEXStatus == "not_affected" {
		t.Fatalf("vulnerable jar: %+v", vuln)
	}
	if vuln.State != "exploitable" || vuln.VEXStatus != "affected" {
		t.Fatalf("vulnerable jar: state=%s vex=%s", vuln.State, vuln.VEXStatus)
	}
	removed := importAndDrill(t, root, dir, "jar-log4j-class-removed", false)
	if removed.State != "needs_review" || removed.VEXStatus != "under_investigation" {
		t.Fatalf("class-removed jar on a draft pack: state=%s vex=%s", removed.State, removed.VEXStatus)
	}
}

func TestImportJarRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	if _, err := w.Create("../../etc/cron.d/x"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "evil.jar")
	out := filepath.Join(dir, "snap.json")
	if err := os.WriteFile(in, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Execute([]string{
		"import", "jar", "--input", in, "--out", out,
		"--asset-id", "x", "--asset-name", "x",
		"--kb-version", "demo-2026.11.08", "--evaluation-time", "2026-11-08T12:00:00Z",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "traverses upward") {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatal("snapshot written for a refused archive")
	}
}
