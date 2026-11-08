// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package cli is the Cobra front end. Evaluation itself is in internal/engine.
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/buildinfo"
	"github.com/uddeshya-world/verdict/internal/canonjson"
	"github.com/uddeshya-world/verdict/internal/engine"
	"github.com/uddeshya-world/verdict/internal/export/openvex"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/policy"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// ExitError is a process exit code with a message.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// Execute runs the CLI with the given args.
func Execute(args []string, stdout, stderr io.Writer) error {
	root := newRoot(stdout, stderr)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	return root.Execute()
}

func newRoot(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:   "verdict",
		Short: "Offline CVE exploitability verdicts from evidence-backed condition packs",
		Long: `Verdict evaluates a condition pack against a local snapshot and writes
a deterministic JSON verdict plus OpenVEX. It does not scan networks, run
exploits, or contact a knowledge service. Evaluation time and the knowledge
bundle version are explicit inputs.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersion())
	root.AddCommand(newPack(stdout, stderr))
	root.AddCommand(newDrill(stdout, stderr))
	root.AddCommand(newOpenVEX())
	return root
}

func newVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the foundation version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", buildinfo.ModulePath, buildinfo.Version)
			return nil
		},
	}
}

func newPack(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pack",
		Short: "Lint or test condition packs",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "lint FILE...",
		Short: "Reject unknown fields, unknown check kinds, and malformed trees",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			for _, path := range args {
				data, err := os.ReadFile(path)
				if err != nil {
					return &ExitError{Code: 2, Err: err}
				}
				if _, err := pack.Load(path, data); err != nil {
					fmt.Fprintf(stderr, "%s: %v\n", path, err)
					return &ExitError{Code: 2, Err: fmt.Errorf("lint failed")}
				}
				fmt.Fprintf(stdout, "%s: ok\n", path)
			}
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "test FILE...",
		Short: "Run a pack's declared snapshot fixtures in process",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			failed := false
			for _, path := range args {
				if err := testPack(path, stdout); err != nil {
					fmt.Fprintf(stderr, "%s: %v\n", path, err)
					failed = true
				}
			}
			if failed {
				return &ExitError{Code: 2, Err: fmt.Errorf("pack test failed")}
			}
			return nil
		},
	})
	return cmd
}

func testPack(path string, stdout io.Writer) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	p, err := pack.Load(path, data)
	if err != nil {
		return err
	}
	if len(p.Tests) == 0 {
		fmt.Fprintf(stdout, "%s: no tests declared\n", path)
		return nil
	}
	for _, tc := range p.Tests {
		snapPath := tc.Snapshot
		if !filepath.IsAbs(snapPath) {
			snapPath = filepath.Join(filepath.Dir(path), snapPath)
		}
		raw, err := os.ReadFile(snapPath)
		if err != nil {
			return err
		}
		snap, err := snapshot.Load(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", tc.Name, err)
		}
		pol, err := loadPolicy(path, tc.Policy)
		if err != nil {
			return fmt.Errorf("%s: %w", tc.Name, err)
		}
		evalAt, err := time.Parse(time.RFC3339, snap.EvaluationTime)
		if err != nil {
			return err
		}
		rep, err := engine.Evaluate(engine.Input{
			Pack: p, Policy: pol, Snapshot: snap, EvaluationTime: evalAt, KBVersion: snap.KBVersion,
		})
		if err != nil {
			return fmt.Errorf("%s: %w", tc.Name, err)
		}
		var got *engine.Verdict
		for i := range rep.Verdicts {
			if rep.Verdicts[i].AssetID == tc.Asset {
				got = &rep.Verdicts[i]
				break
			}
		}
		if got == nil {
			return fmt.Errorf("%s: asset %s not in snapshot", tc.Name, tc.Asset)
		}
		if got.State != tc.ExpectState || got.VEXStatus != tc.ExpectVEX {
			return fmt.Errorf("%s: asset %s state=%s vex=%s, want state=%s vex=%s", tc.Name, tc.Asset, got.State, got.VEXStatus, tc.ExpectState, tc.ExpectVEX)
		}
		if tc.ExpectJustification != "" && got.Justification != tc.ExpectJustification {
			return fmt.Errorf("%s: justification %q, want %q", tc.Name, got.Justification, tc.ExpectJustification)
		}
		if tc.ExpectState == "not_affected" && got.Justification == "" {
			return fmt.Errorf("%s: not_affected without justification", tc.Name)
		}
		if tc.ExpectExposureUncertainty != nil && got.ExposureUncertainty != *tc.ExpectExposureUncertainty {
			return fmt.Errorf("%s: exposure_uncertainty=%v, want %v", tc.Name, got.ExposureUncertainty, *tc.ExpectExposureUncertainty)
		}
		if got.State == "not_affected" && p.Metadata.Status != "reviewed" {
			return fmt.Errorf("%s: not_affected from non-reviewed pack", tc.Name)
		}
		fmt.Fprintf(stdout, "%s: %s %s %s\n", path, tc.Name, got.AssetID, got.State)
	}
	return nil
}

func loadPolicy(packPath, rel string) (*policy.Policy, error) {
	if rel == "" {
		return nil, nil
	}
	path := rel
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(packPath), path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return policy.Load(data)
}

func newDrill(stdout, stderr io.Writer) *cobra.Command {
	var packPath, snapPath, policyPath, outPath, vexPath, author, evalFlag, kbFlag, asset string
	cmd := &cobra.Command{
		Use:   "drill",
		Short: "Evaluate one pack against a local snapshot",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if packPath == "" || snapPath == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--pack and --snapshot are required")}
			}
			pdata, err := os.ReadFile(packPath)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			p, err := pack.Load(packPath, pdata)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			sdata, err := os.ReadFile(snapPath)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			snap, err := snapshot.Load(sdata)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			var pol *policy.Policy
			if policyPath != "" {
				pdata, err := os.ReadFile(policyPath)
				if err != nil {
					return &ExitError{Code: 2, Err: err}
				}
				pol, err = policy.Load(pdata)
				if err != nil {
					return &ExitError{Code: 2, Err: err}
				}
			}
			if asset != "" {
				var found []snapshot.Asset
				for _, a := range snap.Assets {
					if a.ID == asset {
						found = append(found, a)
					}
				}
				if len(found) == 0 {
					return &ExitError{Code: 2, Err: fmt.Errorf("asset %q not in snapshot", asset)}
				}
				snap.Assets = found
			}
			evalAt, err := time.Parse(time.RFC3339, snap.EvaluationTime)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			kb := snap.KBVersion
			if evalFlag != "" {
				evalAt, err = time.Parse(time.RFC3339, evalFlag)
				if err != nil {
					return &ExitError{Code: 2, Err: fmt.Errorf("--evaluation-time: %w", err)}
				}
			}
			if kbFlag != "" {
				kb = kbFlag
			}
			rep, err := engine.Evaluate(engine.Input{
				Pack: p, Policy: pol, Snapshot: snap, EvaluationTime: evalAt, KBVersion: kb,
			})
			if err != nil {
				return &ExitError{Code: 1, Err: err}
			}
			body, err := canonjson.Marshal(rep)
			if err != nil {
				return err
			}
			if outPath == "" {
				if _, err := stdout.Write(body); err != nil {
					return err
				}
			} else if err := os.WriteFile(outPath, body, 0o644); err != nil {
				return err
			}
			for _, v := range rep.Verdicts {
				fmt.Fprintf(stderr, "asset=%s state=%s vex=%s confidence=%s exposure_uncertainty=%t\n",
					v.AssetID, v.State, v.VEXStatus, v.Confidence, v.ExposureUncertainty)
			}
			s := rep.Summary
			fmt.Fprintf(stderr, "summary exploitable=%d vulnerable_not_exposed=%d not_affected=%d needs_review=%d assets=%d\n",
				s.Exploitable, s.VulnerableNotExposed, s.NotAffected, s.NeedsReview, s.Assets)
			if vexPath != "" {
				if author == "" {
					return &ExitError{Code: 2, Err: fmt.Errorf("--author is required with --openvex and is not authenticated")}
				}
				doc, err := openvex.FromReport(rep, author)
				if err != nil {
					return err
				}
				raw, err := openvex.Marshal(doc)
				if err != nil {
					return err
				}
				if err := os.WriteFile(vexPath, raw, 0o644); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&packPath, "pack", "", "condition pack YAML")
	cmd.Flags().StringVar(&snapPath, "snapshot", "", "local inventory snapshot JSON")
	cmd.Flags().StringVar(&policyPath, "policy", "", "site zone policy JSON; without it exposure stays unknown")
	cmd.Flags().StringVar(&outPath, "out", "", "write the JSON report here instead of stdout")
	cmd.Flags().StringVar(&vexPath, "openvex", "", "write an OpenVEX 0.2 document")
	cmd.Flags().StringVar(&author, "author", "", "operator-supplied OpenVEX author label; not authenticated")
	cmd.Flags().StringVar(&evalFlag, "evaluation-time", "", "override snapshot evaluation_time (RFC3339)")
	cmd.Flags().StringVar(&kbFlag, "kb-version", "", "override snapshot kb_version")
	cmd.Flags().StringVar(&asset, "asset", "", "evaluate a single asset id")
	return cmd
}

func newOpenVEX() *cobra.Command {
	var schema string
	cmd := &cobra.Command{
		Use:   "openvex",
		Short: "Check OpenVEX documents",
	}
	val := &cobra.Command{
		Use:   "validate FILE",
		Short: "Validate a document against the shipped OpenVEX schema",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			if err := openvex.Validate(schema, data); err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "openvex: valid")
			return nil
		},
	}
	val.Flags().StringVar(&schema, "schema", "", "OpenVEX JSON Schema path; empty uses the schema embedded in the binary")
	cmd.AddCommand(val)
	return cmd
}

// MarshalReport is used by tests that want the same bytes as --out.
func MarshalReport(rep *engine.Report) ([]byte, error) {
	return canonjson.Marshal(rep)
}

// DecodeReport reads a canonical report. Unknown fields are rejected.
func DecodeReport(data []byte) (*engine.Report, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rep engine.Report
	if err := dec.Decode(&rep); err != nil {
		return nil, err
	}
	return &rep, nil
}
