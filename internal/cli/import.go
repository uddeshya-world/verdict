// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/canonjson"
	"github.com/uddeshya-world/verdict/internal/importer"
)

func newImport(stdout, stderr interface{ Write([]byte) (int, error) }) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Build a local snapshot from a file already on disk",
		Long: `Import reads CycloneDX or Trivy JSON that you already have.
It does not download SBOMs or advisory feeds. Trivy vulnerability decisions
are not copied. Advisory status is a separate local file you write.`,
	}
	cmd.AddCommand(newImportSBOM("cyclonedx", stdout, stderr, importer.CycloneDX))
	cmd.AddCommand(newImportSBOM("trivy", stdout, stderr, importer.Trivy))
	cmd.AddCommand(newImportAdvisories(stderr))
	cmd.AddCommand(newImportJar(stdout, stderr))
	cmd.AddCommand(newImportK8s(stdout, stderr))
	cmd.AddCommand(newImportHost(stdout, stderr))
	return cmd
}

type sbomFunc func([]byte, importer.InventoryOptions) (*importer.Result, error)

func newImportSBOM(name string, stdout, stderr interface{ Write([]byte) (int, error) }, parse sbomFunc) *cobra.Command {
	var input, out, assetID, assetName, kind, basis, confidence, evidenceID, kb, evalAt, observedAt string
	var zones []string
	var complete bool
	cmd := &cobra.Command{
		Use:   name,
		Short: "Import one " + name + " JSON document as one snapshot asset",
		RunE: func(*cobra.Command, []string) error {
			if input == "" || out == "" || assetID == "" || assetName == "" || kb == "" || evalAt == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--input, --out, --asset-id, --asset-name, --kb-version, and --evaluation-time are required")}
			}
			if _, err := time.Parse(time.RFC3339, evalAt); err != nil {
				return &ExitError{Code: 2, Err: fmt.Errorf("--evaluation-time: %w", err)}
			}
			if observedAt == "" {
				observedAt = evalAt
			}
			if _, err := time.Parse(time.RFC3339, observedAt); err != nil {
				return &ExitError{Code: 2, Err: fmt.Errorf("--observed-at: %w", err)}
			}
			if evidenceID == "" {
				evidenceID = "e-import-" + assetID
			}
			data, err := os.ReadFile(input)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			got, err := parse(data, importer.InventoryOptions{
				AssetID: assetID, AssetName: assetName, AssetKind: kind, Zones: zones,
				Complete: complete, Basis: basis, Confidence: confidence,
				ObservedAt: observedAt, EvidenceID: evidenceID, KBVersion: kb, Evaluation: evalAt,
			})
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			for _, n := range got.Notes {
				fmt.Fprintf(stderr, "note: %s\n", n)
			}
			for _, s := range got.Skipped {
				fmt.Fprintf(stderr, "skipped %s\n", s)
			}
			body, err := canonjson.Marshal(got.Snapshot)
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, body, 0o644); err != nil {
				return err
			}
			summary := fmt.Sprintf("import %s: asset=%s packages=%d skipped=%d",
				name, assetID, len(got.Snapshot.Assets[0].Inventory.Packages), len(got.Skipped))
			if len(got.Skipped) > 0 {
				summary += " (" + strings.Join(importer.SkippedNames(got.Skipped), ", ") + ")"
			}
			fmt.Fprintln(stdout, summary)
			return nil
		},
	}
	cmd.Flags().StringVar(&input, "input", "", "local JSON file")
	cmd.Flags().StringVar(&out, "out", "", "snapshot JSON to write")
	cmd.Flags().StringVar(&assetID, "asset-id", "", "snapshot asset id")
	cmd.Flags().StringVar(&assetName, "asset-name", "", "snapshot asset name")
	cmd.Flags().StringVar(&kind, "kind", "host", "asset kind")
	cmd.Flags().StringSliceVar(&zones, "zone", nil, "asset zone label; repeat for more than one. This is not an exposure observation")
	cmd.Flags().BoolVar(&complete, "complete", false, "mark the imported inventory complete")
	cmd.Flags().StringVar(&basis, "basis", "attested", "observed, attested, or inferred")
	cmd.Flags().StringVar(&confidence, "confidence", "medium", "low, medium, high, or confirmed")
	cmd.Flags().StringVar(&evidenceID, "evidence-id", "", "evidence id for the inventory")
	cmd.Flags().StringVar(&kb, "kb-version", "", "knowledge-bundle version string")
	cmd.Flags().StringVar(&evalAt, "evaluation-time", "", "RFC3339 evaluation time; the clock is not read")
	cmd.Flags().StringVar(&observedAt, "observed-at", "", "RFC3339 time the SBOM was observed; defaults to --evaluation-time")
	return cmd
}

func newImportAdvisories(stderr interface{ Write([]byte) (int, error) }) *cobra.Command {
	var snapPath, advPath, out string
	var allowUnmatched bool
	var maxBytes int64
	cmd := &cobra.Command{
		Use:   "advisories",
		Short: "Merge a local advisory file into a snapshot",
		Long: `Each row names one asset, one package URL, and one of affected, fixed, or not_affected.
The file is not downloaded. A row you do not write does not become a status.

A row matches inventory packages with the same type, namespace, name, and
version (an rpm/deb epoch may be in the version or the epoch qualifier).
The arch and upstream qualifiers are ignored. A distro qualifier on the row
must equal the package's; a row without one matches any distro. The fact is
written on each matched package's exact purl. A row that matches nothing
fails the import unless --allow-unmatched, which drops it.`,
		RunE: func(*cobra.Command, []string) error {
			if snapPath == "" || advPath == "" || out == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--snapshot, --advisories, and --out are required")}
			}
			snap, err := loadSnapshotFile(snapPath, maxBytes)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			araw, err := os.ReadFile(advPath)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			doc, err := importer.ParseAdvisories(araw)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			next, rep, err := importer.ApplyAdvisories(snap, doc, importer.AdvisoryOptions{AllowUnmatched: allowUnmatched})
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			for _, m := range rep.Matched {
				fmt.Fprintf(stderr, "matched %s\n", m)
			}
			for _, u := range rep.Unmatched {
				fmt.Fprintf(stderr, "warning: unmatched row dropped: %s\n", u)
			}
			body, err := canonjson.Marshal(next)
			if err != nil {
				return err
			}
			if err := checkSnapshotSize(body, maxBytes); err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			if err := os.WriteFile(out, body, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(stderr, "import advisories: rows=%d matched=%d unmatched=%d facts=%d\n",
				len(doc.Facts), len(rep.Matched), len(rep.Unmatched), rep.Facts)
			return nil
		},
	}
	cmd.Flags().StringVar(&snapPath, "snapshot", "", "snapshot JSON to update")
	cmd.Flags().StringVar(&advPath, "advisories", "", "local advisory JSON")
	cmd.Flags().StringVar(&out, "out", "", "snapshot JSON to write")
	cmd.Flags().BoolVar(&allowUnmatched, "allow-unmatched", false, "drop rows that match no inventory package instead of failing")
	addMaxSnapshotBytes(cmd, &maxBytes)
	return cmd
}
