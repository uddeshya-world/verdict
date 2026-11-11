// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/canonjson"
	"github.com/uddeshya-world/verdict/internal/importer"
)

func newImportHost(stdout, stderr interface{ Write([]byte) (int, error) }) *cobra.Command {
	var input, out, assetID, assetName, kind, kb, evalAt string
	var zones, reachable []string
	var complete bool
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Import one scripts/collect-host.sh JSON document as one snapshot asset",
		Long: `Host reads the JSON that scripts/collect-host.sh printed on a Linux host.
The collector runs on the host, not here: this command does not connect to it.
Facts the collector omitted stay unknown. Listening ports become exposure only
with --reachable-from, which is your statement of which zones reach the host.`,
		RunE: func(*cobra.Command, []string) error {
			if input == "" || out == "" || assetID == "" || kb == "" || evalAt == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--input, --out, --asset-id, --kb-version, and --evaluation-time are required")}
			}
			if _, err := time.Parse(time.RFC3339, evalAt); err != nil {
				return &ExitError{Code: 2, Err: fmt.Errorf("--evaluation-time: %w", err)}
			}
			data, err := os.ReadFile(input)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			got, err := importer.Host(data, importer.HostOptions{
				AssetID: assetID, AssetName: assetName, AssetKind: kind, Zones: zones,
				Complete: complete, ReachableFrom: reachable, KBVersion: kb, Evaluation: evalAt,
			})
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			for _, s := range got.Skipped {
				fmt.Fprintf(stderr, "skipped %s\n", s)
			}
			for _, n := range got.Notes {
				fmt.Fprintf(stderr, "note %q\n", n)
			}
			body, err := canonjson.Marshal(got.Snapshot)
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, body, 0o644); err != nil {
				return err
			}
			a := got.Snapshot.Assets[0]
			fmt.Fprintf(stdout, "import host: asset=%s packages=%d facts=%d exposure=%d skipped=%d\n",
				assetID, len(a.Inventory.Packages), len(a.Facts), len(a.Exposure), len(got.Skipped))
			return nil
		},
	}
	cmd.Flags().StringVar(&input, "input", "", "collect-host.sh JSON file")
	cmd.Flags().StringVar(&out, "out", "", "snapshot JSON to write")
	cmd.Flags().StringVar(&assetID, "asset-id", "", "snapshot asset id")
	cmd.Flags().StringVar(&assetName, "asset-name", "", "snapshot asset name; defaults to the collected hostname")
	cmd.Flags().StringVar(&kind, "kind", "host", "asset kind")
	cmd.Flags().StringSliceVar(&zones, "zone", nil, "asset zone label; repeat for more than one. This is not an exposure observation")
	cmd.Flags().StringSliceVar(&reachable, "reachable-from", nil, "zones that reach the listening ports; repeat for more than one. Without it no exposure is written")
	cmd.Flags().BoolVar(&complete, "complete", false, "mark the package list complete; refused if any package line was unparsed")
	cmd.Flags().StringVar(&kb, "kb-version", "", "knowledge-bundle version string")
	cmd.Flags().StringVar(&evalAt, "evaluation-time", "", "RFC3339 evaluation time; the clock is not read")
	return cmd
}
