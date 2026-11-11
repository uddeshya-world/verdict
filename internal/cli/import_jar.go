// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/canonjson"
	"github.com/uddeshya-world/verdict/internal/importer"
)

func newImportJar(stdout, stderr io.Writer) *cobra.Command {
	var inputs, zones []string
	var out, assetID, assetName, kind, kb, evalAt, observedAt, javaVersion string
	var complete bool
	cmd := &cobra.Command{
		Use:   "jar",
		Short: "Inspect local JAR, WAR, or EAR files in memory and write one snapshot asset",
		Long: `jar opens each archive with Go's zip reader, recurses into nested archives
(WEB-INF/lib, BOOT-INF/lib, EAR modules), and never extracts to disk.

Components come from META-INF/maven/<group>/<artifact>/pom.properties. A
manifest is used only when its Implementation-Title is in a fixed table.
Anything else is listed as skipped and no version is invented.

jar.class.org.apache.logging.log4j.core.lookup.JndiLookup is present when the
class is in any scanned archive, absent only when every identified log4j-core
copy lacks it, and omitted otherwise. absent is high confidence only with
--complete (every classpath archive passed); otherwise it is medium, below the
not_affected bar. runtime.jdk9_or_newer is written only
from --java-version, as an attested operator statement. Class file versions
are a compile target and are not read as the runtime.

Depth, entry count, per-entry size, and total size are capped. An archive
that exceeds a cap or holds an unsafe entry name is refused.`,
		RunE: func(*cobra.Command, []string) error {
			if len(inputs) == 0 || out == "" || assetID == "" || assetName == "" || kb == "" || evalAt == "" {
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
			limits := importer.DefaultJarLimits()
			var archives []importer.JarInput
			for _, p := range inputs {
				data, err := readCapped(p, limits.MaxTotalBytes)
				if err != nil {
					return &ExitError{Code: 2, Err: err}
				}
				archives = append(archives, importer.JarInput{Name: p, Data: data})
			}
			got, err := importer.Jar(archives, importer.JarOptions{
				AssetID: assetID, AssetName: assetName, AssetKind: kind, Zones: zones,
				Complete: complete, ObservedAt: observedAt, KBVersion: kb, Evaluation: evalAt,
				JavaVersion: javaVersion, Limits: limits,
			})
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			for _, s := range got.Skipped {
				fmt.Fprintf(stderr, "skipped %s\n", s)
			}
			for _, n := range got.Notes {
				fmt.Fprintf(stderr, "note %s\n", n)
			}
			body, err := canonjson.Marshal(got.Snapshot)
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, body, 0o644); err != nil {
				return err
			}
			a := got.Snapshot.Assets[0]
			fmt.Fprintf(stdout, "import jar: asset=%s packages=%d facts=%d skipped=%d\n",
				assetID, len(a.Inventory.Packages), len(a.Facts), len(got.Skipped))
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&inputs, "input", nil, "local JAR, WAR, or EAR; repeat for more than one")
	cmd.Flags().StringVar(&out, "out", "", "snapshot JSON to write")
	cmd.Flags().StringVar(&assetID, "asset-id", "", "snapshot asset id")
	cmd.Flags().StringVar(&assetName, "asset-name", "", "snapshot asset name")
	cmd.Flags().StringVar(&kind, "kind", "app", "asset kind")
	cmd.Flags().StringSliceVar(&zones, "zone", nil, "asset zone label; repeat for more than one. This is not an exposure observation")
	cmd.Flags().BoolVar(&complete, "complete", false, "assert every classpath archive was passed; refused when anything was skipped. Required for a high-confidence JndiLookup absent")
	cmd.Flags().StringVar(&kb, "kb-version", "", "knowledge-bundle version string")
	cmd.Flags().StringVar(&evalAt, "evaluation-time", "", "RFC3339 evaluation time; the clock is not read")
	cmd.Flags().StringVar(&observedAt, "observed-at", "", "RFC3339 time the archives were read; defaults to --evaluation-time")
	cmd.Flags().StringVar(&javaVersion, "java-version", "", "runtime java.version you state, such as 17.0.2 or 1.8.0_292; omitted means runtime.jdk9_or_newer is not written")
	return cmd
}

// readCapped reads a local file and refuses one larger than limit bytes.
func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, limit)
	}
	return data, nil
}
