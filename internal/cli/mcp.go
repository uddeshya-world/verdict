// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/mcp"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func newMCP() *cobra.Command {
	var root, logPath string
	var maxSnap int64
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve read-only Verdict tools to a coding agent over stdio (Model Context Protocol)",
		Long: `mcp runs a Model Context Protocol server on stdin and stdout: JSON-RPC 2.0,
one message per line. It is offline and read-only. Tools: verdict_drill,
verdict_explain, verdict_missing_facts, verdict_diff, verdict_pack_lint,
verdict_pack_test, verdict_pack_hash, verdict_openvex_validate,
verdict_report_validate, verdict_list_packs. Nothing that writes facts,
packs, reviews, bundles, or keys is exposed.

Every path a tool receives must resolve, after symlinks, inside --root.
Drill reports and OpenVEX are written only to ROOT/.verdict-out/ under names
the server chooses. Strings from snapshots and packs are returned under
"untrusted", sanitized and capped at 256 characters.

--log FILE writes every request and response as JSON lines with a sequence
number (mode 0600, truncated at start). Exit 0 when stdin closes.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := snapshot.ValidateCap(maxSnap); err != nil {
				return &ExitError{Code: exitInput, Err: err}
			}
			cfg := mcp.Config{
				Root:             root,
				MaxSnapshotBytes: maxSnap,
				Run:              func(args []string, o, e io.Writer) error { return Execute(args, o, e) },
			}
			if logPath != "" {
				f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
				if err != nil {
					return &ExitError{Code: exitInput, Err: fmt.Errorf("--log: %w", err)}
				}
				defer f.Close()
				cfg.Log = f
			}
			srv, err := mcp.New(cfg)
			if err != nil {
				return &ExitError{Code: exitInput, Err: err}
			}
			if err := srv.Serve(cmd.InOrStdin(), cmd.OutOrStdout()); err != nil {
				return &ExitError{Code: exitFail, Err: err}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&root, "root", ".", "directory every tool path must resolve inside; outputs go to ROOT/.verdict-out/")
	cmd.Flags().StringVar(&logPath, "log", "", "write every request and response to this JSONL file (0600)")
	addMaxSnapshotBytes(cmd, &maxSnap)
	return cmd
}
