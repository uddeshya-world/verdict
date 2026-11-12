// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Command sbom writes a minimal, deterministic CycloneDX 1.5 SBOM for the Go
// modules embedded in a built binary. It reads the build info that the Go
// linker stores (the same data as `go version -m`) using only the standard
// library, so it works on ELF, Mach-O and PE binaries from any host.
//
//	go run ./tools/sbom -bin verdict -version 0.1.0 > verdict.cdx.json
package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
)

type component struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Scope   string `json:"scope,omitempty"`
	Hashes  []hash `json:"hashes,omitempty"`
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type bom struct {
	BOMFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
	Metadata     struct {
		Component component `json:"component"`
	} `json:"metadata"`
	Components []component `json:"components"`
}

func purl(path, version string) string {
	return "pkg:golang/" + path + "@" + version
}

func main() {
	bin := flag.String("bin", "", "path to a Go binary")
	version := flag.String("version", "", "version of the main module (overrides build info)")
	flag.Parse()
	if *bin == "" {
		fmt.Fprintln(os.Stderr, "sbom: -bin is required")
		os.Exit(2)
	}
	if err := run(*bin, *version); err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		os.Exit(1)
	}
}

func run(path, version string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])

	if version == "" {
		version = bi.Main.Version
	}
	var b bom
	b.BOMFormat, b.SpecVersion, b.Version = "CycloneDX", "1.5", 1
	// No clock and no random UUID: the SBOM is a pure function of the binary.
	b.SerialNumber = "urn:uuid:" + digest[0:8] + "-" + digest[8:12] + "-" + digest[12:16] + "-" + digest[16:20] + "-" + digest[20:32]
	b.Metadata.Component = component{
		Type: "application", BOMRef: purl(bi.Main.Path, version), Name: bi.Main.Path,
		Version: version, PURL: purl(bi.Main.Path, version),
		Hashes: []hash{{Alg: "SHA-256", Content: digest}},
	}
	b.Components = []component{}
	for _, d := range bi.Deps {
		m := d
		if d.Replace != nil {
			m = d.Replace
		}
		c := component{Type: "library", BOMRef: purl(m.Path, m.Version), Name: m.Path, Version: m.Version, PURL: purl(m.Path, m.Version), Scope: "required"}
		b.Components = append(b.Components, c)
	}
	sort.Slice(b.Components, func(i, j int) bool { return b.Components[i].BOMRef < b.Components[j].BOMRef })
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}
