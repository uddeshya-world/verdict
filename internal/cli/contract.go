// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/canonjson"
	"github.com/uddeshya-world/verdict/internal/engine"
	"github.com/uddeshya-world/verdict/internal/reportschema"
)

// Exit codes. docs/agents.md is the contract for these.
const (
	exitOK     = 0
	exitFail   = 1 // internal error or a failed gate (bench)
	exitInput  = 2 // usage error, unreadable or invalid input
	exitPolicy = 3 // drill --fail-on matched at least one verdict
)

// writeJSON writes v as canonical JSON (indented, trailing newline).
func writeJSON(w io.Writer, v any) error {
	body, err := canonjson.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func addJSONFlag(cmd *cobra.Command, v *bool) {
	cmd.Flags().BoolVar(v, "json", false, "print one JSON object on stdout instead of the text summary (docs/agents.md)")
}

// fileResult is one file in a multi-file --json result.
type fileResult struct {
	File       string `json:"file"`
	OK         bool   `json:"ok"`
	PackID     string `json:"pack_id,omitempty"`
	PackSHA256 string `json:"pack_sha256,omitempty"`
	Error      string `json:"error,omitempty"`
}

// filesResult is the --json shape of pack lint, pack hash, and report validate.
type filesResult struct {
	Command string       `json:"command"`
	OK      bool         `json:"ok"`
	Files   []fileResult `json:"files"`
}

// explainEntry is one catalog entry as `verdict explain` prints it.
type explainEntry struct {
	Code string `json:"code"`
	engine.ReasonInfo
}

type explainResult struct {
	Command string         `json:"command"`
	OK      bool           `json:"ok"`
	Reasons []explainEntry `json:"reasons"`
}

func newExplain(stdout io.Writer) *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "explain [CODE...] [--all]",
		Short: "Print reason catalog entries as JSON",
		Long: `explain prints the catalog entry for each reason code a drill report can
carry: its kind (leaf, decision, exposure, error), the hint text, the next
action, and who can take it (human, collector, reviewer, agent, none).

Leaf hints are templates: {check} is the check id, {detail} the detail, and
{detail_q} the quoted detail. An unknown code exits 2.`,
		RunE: func(_ *cobra.Command, args []string) error {
			if all == (len(args) > 0) {
				return &ExitError{Code: exitInput, Err: fmt.Errorf("give one or more reason codes, or --all")}
			}
			codes := args
			if all {
				codes = engine.ReasonCodes()
			}
			res := explainResult{Command: "explain", OK: true, Reasons: []explainEntry{}}
			for _, c := range codes {
				info, ok := engine.Reasons[c]
				if !ok {
					return &ExitError{Code: exitInput, Err: fmt.Errorf("unknown reason code %q; verdict explain --all lists them", c)}
				}
				res.Reasons = append(res.Reasons, explainEntry{Code: c, ReasonInfo: info})
			}
			return writeJSON(stdout, res)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "print every catalog entry")
	return cmd
}

func newReport(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Check drill report files",
	}
	var asJSON bool
	val := &cobra.Command{
		Use:   "validate FILE...",
		Short: "Validate drill reports against the embedded report schema and reason catalog",
		Long: `validate checks each file against schemas/report.schema.json (embedded in
the binary) and checks that every reason code is in the reason catalog.
Every file is checked. Any invalid file exits 2.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			res := filesResult{Command: "report validate", OK: true, Files: []fileResult{}}
			for _, path := range args {
				r := fileResult{File: path, OK: true}
				data, err := os.ReadFile(path)
				if err == nil {
					err = reportschema.Validate(data)
				}
				if err != nil {
					r.OK, r.Error, res.OK = false, err.Error(), false
					if !asJSON {
						fmt.Fprintf(stderr, "%s: %v\n", path, err)
					}
				} else if !asJSON {
					fmt.Fprintf(stdout, "%s: valid\n", path)
				}
				res.Files = append(res.Files, r)
			}
			if asJSON {
				if err := writeJSON(stdout, res); err != nil {
					return err
				}
			}
			if !res.OK {
				return &ExitError{Code: exitInput, Err: fmt.Errorf("report validate failed")}
			}
			return nil
		},
	}
	addJSONFlag(val, &asJSON)
	cmd.AddCommand(val)
	return cmd
}

// failOnValues are the drill --fail-on policies.
var failOnValues = map[string]func(state string) bool{
	"exploitable": func(s string) bool { return s == "exploitable" },
	"affected":    func(s string) bool { return s == "exploitable" || s == "vulnerable_not_exposed" },
	"needs_review": func(s string) bool {
		return s == "needs_review"
	},
	"not_cleared": func(s string) bool { return s != "not_affected" },
}

// failOnMatches counts the verdicts the policy matches.
func failOnMatches(policy string, rep *engine.Report) int {
	match := failOnValues[policy]
	n := 0
	for _, v := range rep.Verdicts {
		if match(v.State) {
			n++
		}
	}
	return n
}

// One-line summary shapes for --json. Each is written only on success; a
// failure exits non-zero with the error on stderr and nothing on stdout.

type importSBOMResult struct {
	Command      string   `json:"command"`
	OK           bool     `json:"ok"`
	Out          string   `json:"out"`
	AssetID      string   `json:"asset_id"`
	Packages     int      `json:"packages"`
	Skipped      int      `json:"skipped"`
	SkippedNames []string `json:"skipped_names"`
}

type importAssetResult struct {
	Command  string `json:"command"`
	OK       bool   `json:"ok"`
	Out      string `json:"out"`
	AssetID  string `json:"asset_id"`
	Packages int    `json:"packages"`
	Facts    int    `json:"facts"`
	Exposure int    `json:"exposure"`
	Skipped  int    `json:"skipped"`
}

type importK8sResult struct {
	Command string `json:"command"`
	OK      bool   `json:"ok"`
	Out     string `json:"out"`
	Cluster string `json:"cluster"`
	Assets  int    `json:"assets"`
	Notes   int    `json:"notes"`
}

type importAdvisoriesResult struct {
	Command   string `json:"command"`
	OK        bool   `json:"ok"`
	Out       string `json:"out"`
	Rows      int    `json:"rows"`
	Matched   int    `json:"matched"`
	Unmatched int    `json:"unmatched"`
	Facts     int    `json:"facts"`
}

type snapshotResult struct {
	Command string `json:"command"`
	OK      bool   `json:"ok"`
	Out     string `json:"out"`
	Edits   int    `json:"edits"`
	Assets  int    `json:"assets"`
}

type bundleVerifyResult struct {
	Command   string `json:"command"`
	OK        bool   `json:"ok"`
	KBVersion string `json:"kb_version"`
	CreatedAt string `json:"created_at"`
	KeyID     string `json:"key_id"`
	Files     int    `json:"files"`
}
