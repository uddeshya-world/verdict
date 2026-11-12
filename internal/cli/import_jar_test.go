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
	"time"

	"github.com/uddeshya-world/verdict/internal/engine"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/policy"
	"github.com/uddeshya-world/verdict/internal/snapshot"
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

// evalReviewed drills a snapshot against the log4j pack with the reviewed bar
// applied in memory, the way internal/bench does. The pack file is unchanged.
func evalReviewed(t *testing.T, root, snapPath string) engine.Verdict {
	t.Helper()
	packPath := filepath.Join(root, "packs/draft/ecp-cve-2021-44228-log4j.yaml")
	pdata, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pack.Load(packPath, pdata)
	if err != nil {
		t.Fatal(err)
	}
	p.Metadata.Status = "reviewed"
	p.Metadata.Reviewers = []pack.Person{{Name: "synthetic-reviewer-alpha"}, {Name: "synthetic-reviewer-beta"}}
	poldata, err := os.ReadFile(filepath.Join(root, "examples/policy/lab-zones.json"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(poldata)
	if err != nil {
		t.Fatal(err)
	}
	sdata, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := snapshot.Load(sdata)
	if err != nil {
		t.Fatal(err)
	}
	evalAt, err := time.Parse(time.RFC3339, snap.EvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := engine.Evaluate(engine.Input{Pack: p, Policy: pol, Snapshot: snap, EvaluationTime: evalAt, KBVersion: snap.KBVersion})
	if err != nil {
		t.Fatal(err)
	}
	return rep.Verdicts[0]
}

// A host can carry log4j-core on a classpath the operator did not pass, such
// as an application server lib directory. Without --complete, a removed class
// in the scanned archives must not clear the CVE even under a reviewed pack.
func TestImportJarClassRemovedNeverNotAffectedWithoutComplete(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	importAndDrill(t, root, dir, "jar-partial", false)
	v := evalReviewed(t, root, filepath.Join(dir, "jar-partial.json"))
	if v.State == "not_affected" || v.VEXStatus == "not_affected" {
		t.Fatalf("partial classpath produced not_affected under a reviewed pack: %+v", v)
	}
	// Control: the same bytes declared complete do reach the reviewed bar, so the
	// assertion above is held by the medium confidence and not by something else.
	importAndDrill(t, root, dir, "jar-complete", false, "--complete")
	v = evalReviewed(t, root, filepath.Join(dir, "jar-complete.json"))
	if v.State != "not_affected" {
		t.Fatalf("control: complete classpath with class removed: state=%s vex=%s reasons=%v", v.State, v.VEXStatus, v.Reasons)
	}
}

func zipBytes(t *testing.T, files [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, f := range files {
		fw, err := w.CreateHeader(&zip.FileHeader{Name: f[0], Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(f[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func importJarFile(t *testing.T, dir, id string, data []byte, extra ...string) (string, error) {
	t.Helper()
	in := filepath.Join(dir, id+".jar")
	if err := os.WriteFile(in, data, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, id+".json")
	var stdout, stderr bytes.Buffer
	err := Execute(append([]string{
		"import", "jar", "--input", in, "--out", out,
		"--asset-id", id, "--asset-name", id, "--zone", "internet",
		"--kb-version", "demo-2026.11.08",
		"--evaluation-time", "2026-11-08T12:00:00Z",
		"--observed-at", "2026-11-08T11:00:00Z",
	}, extra...), &stdout, &stderr)
	return out, err
}

var log4jCoreFiles = [][2]string{
	{"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties", "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n"},
	{"org/apache/logging/log4j/core/Logger.class", "\xca\xfe\xba\xbe"},
}

// F11: log4j-core coordinates and classes, JndiLookup relocated by a shading
// plugin. Even with --complete under a reviewed pack it is never not_affected.
func TestImportJarRelocatedJndiLookupNeverNotAffected(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	data := zipBytes(t, append(append([][2]string{}, log4jCoreFiles...), [2]string{"com/acme/shade/lookup/JndiLookup.class", "\xca\xfe\xba\xbe"}))
	snap, err := importJarFile(t, dir, "jar-relocated", data, "--complete")
	if err != nil {
		t.Fatal(err)
	}
	if v := evalReviewed(t, root, snap); v.State == "not_affected" || v.VEXStatus == "not_affected" {
		t.Fatalf("relocated JndiLookup produced not_affected: %+v", v)
	}
}

// F12: log4j-core with JndiLookup inside a nested .zip is found, and an
// archive format that is not read refuses --complete.
func TestImportJarNestedZip(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	core := zipBytes(t, append(append([][2]string{}, log4jCoreFiles...), [2]string{"org/apache/logging/log4j/core/lookup/JndiLookup.class", "\xca\xfe\xba\xbe"}))
	outer := zipBytes(t, [][2]string{{"lib/deps.zip", string(zipBytes(t, [][2]string{{"log4j-core-2.14.1.jar", string(core)}}))}})
	snap, err := importJarFile(t, dir, "jar-nested-zip", outer, "--complete")
	if err != nil {
		t.Fatal(err)
	}
	if v := evalReviewed(t, root, snap); v.State != "exploitable" {
		t.Fatalf("nested zip: state=%s reasons=%v", v.State, v.Reasons)
	}
	removed := zipBytes(t, log4jCoreFiles)
	tarred := zipBytes(t, [][2]string{{"log4j-core.jar", string(removed)}, {"lib/more.tar.gz", "opaque"}})
	out, err := importJarFile(t, dir, "jar-tarball", tarred, "--complete")
	if err == nil || !strings.Contains(err.Error(), "cannot be complete") {
		t.Fatalf("--complete accepted with an unscanned tarball: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatal("snapshot written for a refused --complete")
	}
}
