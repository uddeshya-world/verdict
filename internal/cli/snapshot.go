// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
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

// loadSnapshotFile refuses an oversized file before reading it when its size
// is known, and otherwise reads at most maxBytes+1 bytes.
func loadSnapshotFile(path string, maxBytes int64) (*snapshot.Snapshot, error) {
	if err := snapshot.ValidateCap(maxBytes); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var buf bytes.Buffer
	if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() {
		if fi.Size() > maxBytes {
			return nil, fmt.Errorf("%s: snapshot is %d bytes, over the %d-byte cap; raise it with --max-snapshot-bytes", path, fi.Size(), maxBytes)
		}
		buf.Grow(int(fi.Size()) + 1)
	}
	if _, err := buf.ReadFrom(io.LimitReader(f, maxBytes+1)); err != nil {
		return nil, err
	}
	if int64(buf.Len()) > maxBytes {
		return nil, fmt.Errorf("%s: snapshot is over the %d-byte cap; raise it with --max-snapshot-bytes", path, maxBytes)
	}
	s, err := snapshot.LoadMax(buf.Bytes(), maxBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// checkSnapshotSize validates the cap and refuses to write a snapshot that
// the same cap would refuse to read back.
func checkSnapshotSize(body []byte, maxBytes int64) error {
	if err := snapshot.ValidateCap(maxBytes); err != nil {
		return err
	}
	if int64(len(body)) > maxBytes {
		return fmt.Errorf("snapshot: output is %d bytes, over the %d-byte cap; raise it with --max-snapshot-bytes", len(body), maxBytes)
	}
	return nil
}

// writeSnapshot checks the cap and writes body to out.
func writeSnapshot(out string, body []byte, maxBytes int64) error {
	if err := checkSnapshotSize(body, maxBytes); err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	return os.WriteFile(out, body, 0o644)
}
