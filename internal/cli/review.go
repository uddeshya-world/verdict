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
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "review",
		Short: "Check a review record against a pack file",
		Long: `review checks that a record names two reviewers and the pack content.
The hash ignores metadata.status and metadata.reviewers, so setting
status to reviewed does not invalidate a record made against the draft.
It does not edit the pack and it does not decide that a name belongs to a real person.
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
			names := pack.SortedNames(pack.ReviewerNames(rec))
			if asJSON {
				if err := writeJSON(stdout, reviewResult{
					Command: "pack review", OK: true, PackID: p.Metadata.ID,
					PackStatus: p.Metadata.Status, Reviewers: append([]string{}, names...),
				}); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(stdout, "review record ok pack=%s reviewers=%s\n", p.Metadata.ID, strings.Join(names, ","))
			}
			if p.Metadata.Status != "reviewed" {
				fmt.Fprintf(stderr, "pack status is %s. This command does not change it.\n", p.Metadata.Status)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&packPath, "pack", "", "pack file")
	cmd.Flags().StringVar(&recordPath, "record", "", "review record JSON")
	addJSONFlag(cmd, &asJSON)
	return cmd
}

// reviewResult is the pack review --json shape. It is written only when the
// record checks out; a failed check exits 2 with the error on stderr.
type reviewResult struct {
	Command    string   `json:"command"`
	OK         bool     `json:"ok"`
	PackID     string   `json:"pack_id"`
	PackStatus string   `json:"pack_status"`
	Reviewers  []string `json:"reviewers"`
}

// newPackHash prints the content hash that pack review compares against.
// Output is one line per file: "pack_sha256=<hex> pack=<id> file=<path>".
func newPackHash(stdout, stderr interface{ Write([]byte) (int, error) }) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "hash FILE...",
		Short: "Print the review content hash (pack_sha256) of pack files",
		Long: `hash loads each pack with the same strict loader as lint and review
and prints the pack_sha256 that a review record must carry:

  pack_sha256=<64 hex> pack=<metadata.id> file=<path>

The hash is of the decoded pack with metadata.status and
metadata.reviewers cleared. YAML comments and formatting do not change it;
any other field does. It is not the pack_sha256 in a drill report, which
hashes the file bytes. A file that fails to load prints nothing and the
command exits 2.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			res := filesResult{Command: "pack hash", OK: true, Files: []fileResult{}}
			fail := func(path string, err error, text bool) error {
				if !asJSON {
					if text {
						fmt.Fprintf(stderr, "%s: %v\n", path, err)
						return &ExitError{Code: 2, Err: fmt.Errorf("pack hash failed")}
					}
					return &ExitError{Code: 2, Err: err}
				}
				res.OK = false
				res.Files = append(res.Files, fileResult{File: path, Error: err.Error()})
				if werr := writeJSON(stdout, res); werr != nil {
					return werr
				}
				return &ExitError{Code: 2, Err: fmt.Errorf("pack hash failed")}
			}
			for _, path := range args {
				data, err := os.ReadFile(path)
				if err != nil {
					return fail(path, err, false)
				}
				p, err := pack.Load(path, data)
				if err != nil {
					return fail(path, err, true)
				}
				sum, err := pack.ContentSHA256(p)
				if err != nil {
					return fail(path, err, false)
				}
				if asJSON {
					res.Files = append(res.Files, fileResult{File: path, OK: true, PackID: p.Metadata.ID, PackSHA256: sum})
					continue
				}
				fmt.Fprintf(stdout, "pack_sha256=%s pack=%s file=%s\n", sum, p.Metadata.ID, path)
			}
			if asJSON {
				return writeJSON(stdout, res)
			}
			return nil
		},
	}
	addJSONFlag(cmd, &asJSON)
	return cmd
}
