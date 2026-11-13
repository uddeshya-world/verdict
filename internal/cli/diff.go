// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/diff"
	"github.com/uddeshya-world/verdict/internal/engine"
	"github.com/uddeshya-world/verdict/internal/reportschema"
)

// diffResult is the diff --json shape (docs/agents.md). ok is false exactly
// when the command exits 3.
type diffResult struct {
	Command string `json:"command"`
	OK      bool   `json:"ok"`
	Before  string `json:"before"`
	After   string `json:"after"`
	FailOn  string `json:"fail_on"`
	Matched int    `json:"matched"`
	diff.Result
}

func newDiff(stdout io.Writer) *cobra.Command {
	var asJSON bool
	var failOn string
	cmd := &cobra.Command{
		Use:   "diff BEFORE.json AFTER.json",
		Short: "Compare two drill reports for the same pack and CVE, asset by asset",
		Long: `diff compares two drill reports, for example the base and head of a pull
request. Both are validated first (report schema and reason catalog), exactly
as report validate does. Reports with a different pack_id or cve are refused.
A different pack_sha256, pack_status, policy_sha256, kb_version,
evaluation_time, or tool is listed as a context change, not refused.

Each asset that was added, removed, or changed (state, vex_status,
justification, confidence, exposure_uncertainty, or the set of reasons) is
classed:

  regression   into exploitable from anything else (an added exploitable
               asset too), or out of not_affected
  improvement  out of exploitable, or into not_affected
  neutral      anything else, including every removed asset

diff never re-decides a verdict; it reads each report's state. Reports are
caller-asserted: a removed asset is reported but is not a regression, so use
--fail-on any where omitting an asset must fail the gate.

Exit 0 when --fail-on matches nothing, 3 when it matches, 2 on invalid input.`,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 2 {
				return &ExitError{Code: exitInput, Err: fmt.Errorf("diff takes two report files (BEFORE AFTER), got %d args", len(args))}
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if !diff.ValidFailOn(failOn) {
				return &ExitError{Code: exitInput, Err: fmt.Errorf("--fail-on must be %s", diff.FailOnValues)}
			}
			before, err := loadValidReport(args[0])
			if err != nil {
				return &ExitError{Code: exitInput, Err: err}
			}
			after, err := loadValidReport(args[1])
			if err != nil {
				return &ExitError{Code: exitInput, Err: err}
			}
			res, err := diff.Compare(before, after)
			if err != nil {
				return &ExitError{Code: exitInput, Err: err}
			}
			matched := res.Matches(failOn)
			out := diffResult{
				Command: "diff", OK: len(matched) == 0,
				Before: args[0], After: args[1], FailOn: failOn, Matched: len(matched),
				Result: *res,
			}
			if asJSON {
				if err := writeJSON(stdout, out); err != nil {
					return err
				}
			} else {
				writeDiffText(stdout, &out)
			}
			if len(matched) > 0 {
				return &ExitError{Code: exitPolicy, Err: fmt.Errorf("diff --fail-on %s: %d of %d changed assets match", failOn, len(matched), len(res.Changes))}
			}
			return nil
		},
	}
	addJSONFlag(cmd, &asJSON)
	cmd.Flags().StringVar(&failOn, "fail-on", diff.DefaultFailOn, "exit 3 when a change matches: regression, any-affected-change (also any added, removed, or changed asset that is exploitable or vulnerable_not_exposed on either side), or any (every added, removed, or changed asset)")
	return cmd
}

// loadValidReport reads one report, validates it as report validate does,
// and decodes it.
func loadValidReport(path string) (*engine.Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := reportschema.Validate(data); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var rep engine.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &rep, nil
}

func writeDiffText(w io.Writer, r *diffResult) {
	for _, c := range r.ContextChanges {
		fmt.Fprintf(w, "context %s before=%s after=%s\n", c.Field, textToken(c.Before), textToken(c.After))
	}
	for _, c := range r.Changes {
		before, after := "absent", "absent"
		if c.Before != nil {
			before = c.Before.State
		}
		if c.After != nil {
			after = c.After.State
		}
		line := fmt.Sprintf("asset=%s before=%s after=%s class=%s change=%s", textToken(c.AssetID), before, after, c.Class, c.Kind)
		if len(c.Fields) > 0 {
			line += " fields=" + strings.Join(c.Fields, ",")
		}
		if len(c.ReasonsAdded) > 0 {
			line += " reasons_added=" + strings.Join(c.ReasonsAdded, ",")
		}
		if len(c.ReasonsRemoved) > 0 {
			line += " reasons_removed=" + strings.Join(c.ReasonsRemoved, ",")
		}
		fmt.Fprintln(w, line)
	}
	result := "pass"
	if !r.OK {
		result = "fail"
	}
	n := r.Counts
	fmt.Fprintf(w, "summary added=%d removed=%d changed=%d unchanged=%d regression=%d improvement=%d neutral=%d context_changes=%d fail_on=%s matched=%d result=%s\n",
		n.Added, n.Removed, n.Changed, n.Unchanged, n.Regression, n.Improvement, n.Neutral, len(r.ContextChanges), r.FailOn, r.Matched, result)
}

// textToken prints a caller-supplied string (asset id, kb_version) as is when
// it is plain, and quoted otherwise, so one value is one token on one line and
// never carries a backtick, markup, or control character into a CI summary.
func textToken(s string) string {
	plain := s != ""
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:/@+-", r)) {
			plain = false
			break
		}
	}
	if plain {
		return s
	}
	q := strconv.QuoteToASCII(s)
	for _, esc := range []struct{ from, to string }{{"`", `\x60`}, {"<", `\x3c`}, {">", `\x3e`}, {"&", `\x26`}} {
		q = strings.ReplaceAll(q, esc.from, esc.to)
	}
	return q
}
