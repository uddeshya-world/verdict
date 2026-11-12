// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/canonjson"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func newSnapshot(stdout interface{ Write([]byte) (int, error) }) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Combine local snapshot files",
	}
	var out string
	var maxBytes int64
	merge := &cobra.Command{
		Use:   "merge FILE...",
		Short: "Concatenate assets that share evaluation time and kb version",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if out == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--out is required")}
			}
			parts := make([]*snapshot.Snapshot, 0, len(args))
			for _, path := range args {
				s, err := loadSnapshotFile(path, maxBytes)
				if err != nil {
					return &ExitError{Code: 2, Err: err}
				}
				parts = append(parts, s)
			}
			got, err := snapshot.Merge(parts...)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			body, err := canonjson.Marshal(got)
			if err != nil {
				return err
			}
			if err := checkSnapshotSize(body, maxBytes); err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			if err := os.WriteFile(out, body, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "snapshot merge: assets=%d\n", len(got.Assets))
			return nil
		},
	}
	merge.Flags().StringVar(&out, "out", "", "snapshot JSON to write")
	addMaxSnapshotBytes(merge, &maxBytes)
	cmd.AddCommand(merge)
	return cmd
}

// addMaxSnapshotBytes registers --max-snapshot-bytes on a command that reads
// snapshot files.
func addMaxSnapshotBytes(cmd *cobra.Command, v *int64) {
	cmd.Flags().Int64Var(v, "max-snapshot-bytes", snapshot.DefaultMaxBytes, "largest snapshot document accepted, in bytes")
}

// loadSnapshotFile reads at most maxBytes+1 bytes so an oversized file is
// rejected without reading all of it.
func loadSnapshotFile(path string, maxBytes int64) (*snapshot.Snapshot, error) {
	if maxBytes < 1 {
		return nil, fmt.Errorf("--max-snapshot-bytes must be positive")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	s, err := snapshot.LoadMax(raw, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// checkSnapshotSize refuses to write a snapshot that the same cap would
// refuse to read back.
func checkSnapshotSize(body []byte, maxBytes int64) error {
	if int64(len(body)) > maxBytes {
		return fmt.Errorf("snapshot: output is %d bytes, over the %d-byte cap; raise it with --max-snapshot-bytes", len(body), maxBytes)
	}
	return nil
}
