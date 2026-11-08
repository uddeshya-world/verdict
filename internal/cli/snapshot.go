// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
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
				raw, err := os.ReadFile(path)
				if err != nil {
					return &ExitError{Code: 2, Err: err}
				}
				s, err := snapshot.Load(raw)
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
			if err := os.WriteFile(out, body, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "snapshot merge: assets=%d\n", len(got.Assets))
			return nil
		},
	}
	merge.Flags().StringVar(&out, "out", "", "snapshot JSON to write")
	cmd.AddCommand(merge)
	return cmd
}
