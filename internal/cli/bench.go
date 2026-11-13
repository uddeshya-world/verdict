// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/bench"
	"github.com/uddeshya-world/verdict/internal/canonjson"
	"github.com/uddeshya-world/verdict/internal/rootpath"
)

func newBench(stdout, stderr interface{ Write([]byte) (int, error) }) *cobra.Command {
	var corpus, out string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Score packs against the ground-truth corpus",
		Long: `Bench applies the reviewed decision bar in memory and fails if any
fixture that is not labeled not_affected comes out not_affected.
Draft pack files are not modified, and the in-memory reviewer names are
fixtures. They are not a review of a real CVE.`,
		RunE: func(*cobra.Command, []string) error {
			if corpus == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--corpus is required")}
			}
			root, err := rootpath.Find()
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			raw, err := os.ReadFile(corpus)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			cases, err := bench.LoadCorpus(raw)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			rep, err := bench.Run(root, cases)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			body, err := canonjson.Marshal(rep)
			if err != nil {
				return err
			}
			if out != "" {
				if err := os.WriteFile(out, body, 0o644); err != nil {
					return err
				}
			}
			for _, row := range rep.Rows {
				if row.FalseNotAffected || row.StateMismatch || row.TradeoffMissing {
					fmt.Fprintf(stderr, "FAIL %s state=%s vex=%s %s\n", row.ID, row.State, row.VEXStatus, row.Detail)
				}
			}
			if asJSON {
				if _, err := stdout.Write(body); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(stdout, "bench cases=%d false_not_affected=%d state_mismatches=%d\n", rep.Cases, rep.FalseNotAffected, rep.StateMismatches)
			}
			if rep.FalseNotAffected > 0 || rep.StateMismatches > 0 {
				return &ExitError{Code: 1, Err: fmt.Errorf("verdict-bench gate failed: false_not_affected=%d state_mismatches=%d", rep.FalseNotAffected, rep.StateMismatches)}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&corpus, "corpus", "bench/corpus.json", "ground-truth corpus")
	cmd.Flags().StringVar(&out, "out", "", "write the JSON scoreboard")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the JSON scoreboard (the --out document) on stdout instead of the text line")
	return cmd
}
