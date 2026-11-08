// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/pack"
)

func newPackReview(stdout, stderr interface{ Write([]byte) (int, error) }) *cobra.Command {
	var packPath, recordPath string
	cmd := &cobra.Command{
		Use:   "review",
		Short: "Check a review record against a pack file",
		Long: `review checks that a record names two reviewers and the exact pack bytes.
It does not edit the pack and it does not decide that a name belongs to a real person.
A real CVE stays draft until a human sets status to reviewed using names this command accepted.
synthetic-reviewer-* names cannot sign a real CVE.`,
		RunE: func(*cobra.Command, []string) error {
			if packPath == "" || recordPath == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--pack and --record are required")}
			}
			data, err := os.ReadFile(packPath)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			p, err := pack.Load(packPath, data)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			raw, err := os.ReadFile(recordPath)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			rec, err := pack.ParseReviewRecord(raw)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			if err := pack.CheckReview(p, rec); err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			if p.Metadata.Status == "reviewed" && !pack.SameReviewers(p, rec) {
				return &ExitError{Code: 2, Err: fmt.Errorf("reviewed pack reviewers do not match the record")}
			}
			fmt.Fprintf(stdout, "review record ok pack=%s reviewers=%s\n", p.Metadata.ID, strings.Join(pack.SortedNames(pack.ReviewerNames(rec)), ","))
			if p.Metadata.Status != "reviewed" {
				fmt.Fprintf(stderr, "pack status is %s. This command does not change it.\n", p.Metadata.Status)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&packPath, "pack", "", "pack file")
	cmd.Flags().StringVar(&recordPath, "record", "", "review record JSON")
	return cmd
}
