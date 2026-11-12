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
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/buildinfo"
	"github.com/uddeshya-world/verdict/internal/canonjson"
	"github.com/uddeshya-world/verdict/internal/engine"
	"github.com/uddeshya-world/verdict/internal/export/openvex"
	"github.com/uddeshya-world/verdict/internal/osv"
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
	root.AddCommand(newImport(stdout, stderr))
	root.AddCommand(newSnapshot(stdout))
	root.AddCommand(newBench(stdout, stderr))
	root.AddCommand(newBundle(stdout, stderr))
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
	cmd.AddCommand(newPackReview(stdout, stderr))
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
	var maxSnap int64
	test := &cobra.Command{
		Use:   "test FILE...",
		Short: "Run a pack's declared snapshot fixtures in process",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			failed := false
			for _, path := range args {
				if err := testPack(path, stdout, maxSnap); err != nil {
					fmt.Fprintf(stderr, "%s: %v\n", path, err)
					failed = true
				}
			}
			if failed {
				return &ExitError{Code: 2, Err: fmt.Errorf("pack test failed")}
			}
			return nil
		},
	}
	addMaxSnapshotBytes(test, &maxSnap)
	cmd.AddCommand(test)
	return cmd
}

func testPack(path string, stdout io.Writer, maxSnap int64) error {
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
		snap, err := loadSnapshotFile(snapPath, maxSnap)
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
	var packPath, snapPath, policyPath, outPath, vexPath, author, evalFlag, kbFlag, asset, cveFlag, osvProto, kbDir, pubPath string
	var osvPaths []string
	var osvPort int
	var maxSnap int64
	var maxKBAge string
	var allowOlderKB bool
	cmd := &cobra.Command{
		Use:   "drill",
		Short: "Evaluate one pack, or a version-only OSV fallback, against a local snapshot",
		Long: `drill evaluates a condition pack against a local snapshot.

When no pack exists for a CVE, pass --osv with local OSV records instead of
--pack. Verdict builds a version-only fallback in memory: a draft with a low
confidence ceiling. An in-range package is affected. An absent or
out-of-range package is needs_review, never not_affected. Distro ecosystems
are skipped and need an advisory fact.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sources := 0
			for _, set := range []bool{packPath != "", len(osvPaths) > 0, kbDir != ""} {
				if set {
					sources++
				}
			}
			if snapPath == "" || sources != 1 {
				return &ExitError{Code: 2, Err: fmt.Errorf("--snapshot and exactly one of --pack, --osv, or --kb are required")}
			}
			if kbDir != "" && kbFlag != "" {
				// The signed manifest names the version; an override would make the audit record false.
				return &ExitError{Code: 2, Err: fmt.Errorf("--kb-version cannot be combined with --kb; the report takes kb_version from the signed bundle")}
			}
			if kbDir == "" && (maxKBAge != "" || allowOlderKB) {
				return &ExitError{Code: 2, Err: fmt.Errorf("--max-kb-age and --allow-older-kb need --kb")}
			}
			var maxAge time.Duration
			if maxKBAge != "" {
				var err error
				if maxAge, err = parseAge(maxKBAge); err != nil {
					return &ExitError{Code: 2, Err: fmt.Errorf("--max-kb-age: %w", err)}
				}
			}
			var p *pack.Pack
			var kbRes *kbResolution
			if kbDir != "" {
				res, err := resolveFromKB(kbDir, pubPath, cveFlag, osvPort, osvProto, allowOlderKB)
				if err != nil {
					return &ExitError{Code: 2, Err: err}
				}
				p = res.Pack
				kbRes = res
				for _, n := range res.Notes {
					fmt.Fprintln(stderr, n)
				}
			} else if packPath != "" {
				pdata, err := os.ReadFile(packPath)
				if err != nil {
					return &ExitError{Code: 2, Err: err}
				}
				p, err = pack.Load(packPath, pdata)
				if err != nil {
					return &ExitError{Code: 2, Err: err}
				}
			} else {
				fb, err := loadFallback(osvPaths, cveFlag, osvPort, osvProto)
				if err != nil {
					return &ExitError{Code: 2, Err: err}
				}
				p = fb.Pack
				fmt.Fprintf(stderr, "fallback %s: version-only from OSV, draft, confidence ceiling low. It cannot say not_affected.\n", p.Metadata.ID)
				for _, s := range fb.Skipped {
					fmt.Fprintf(stderr, "fallback skipped: %s\n", s)
				}
			}
			snap, err := loadSnapshotFile(snapPath, maxSnap)
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
			in := engine.Input{Pack: p, Policy: pol, Snapshot: snap, EvaluationTime: evalAt, KBVersion: kb}
			if kbRes != nil {
				newer, err := checkKBAge(kbRes.CreatedAt, evalAt, nowFunc(), maxAge)
				if err != nil {
					return &ExitError{Code: 2, Err: fmt.Errorf("--kb %s: %w", kbDir, err)}
				}
				if newer {
					fmt.Fprintf(stderr, "note: kb is newer than the snapshot (kb created_at %s, evaluation_time %s)\n", kbRes.CreatedAt, evalAt.UTC().Format(time.RFC3339))
				}
				in.KBVersion, in.KBKeyID, in.KBCreatedAt = kbRes.KBVersion, kbRes.KeyID, kbRes.CreatedAt
			} else if kbFlag != "" {
				in.KBVersion = kbFlag
			}
			rep, err := engine.Evaluate(in)
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
	cmd.Flags().StringArrayVar(&osvPaths, "osv", nil, "local OSV record JSON (repeatable); builds a version-only fallback instead of --pack")
	cmd.Flags().StringVar(&kbDir, "kb", "", "installed knowledge version directory (from bundle install); re-verified with --pubkey, then the pack for --cve or its OSV fallback is used")
	cmd.Flags().StringVar(&pubPath, "pubkey", "", "trusted PEM Ed25519 public key for --kb")
	cmd.Flags().StringVar(&cveFlag, "cve", "", "CVE id to select from the OSV records; inferred when they name exactly one")
	cmd.Flags().IntVar(&osvPort, "port", 1, "service port for the fallback exposure check; the default matches no service, so exposure stays unknown")
	cmd.Flags().StringVar(&osvProto, "proto", "tcp", "service protocol for the fallback exposure check")
	cmd.Flags().StringVar(&snapPath, "snapshot", "", "local inventory snapshot JSON")
	cmd.Flags().StringVar(&policyPath, "policy", "", "site zone policy JSON; without it exposure stays unknown")
	cmd.Flags().StringVar(&outPath, "out", "", "write the JSON report here instead of stdout")
	cmd.Flags().StringVar(&vexPath, "openvex", "", "write an OpenVEX 0.2 document")
	cmd.Flags().StringVar(&author, "author", "", "operator-supplied OpenVEX author label; not authenticated")
	cmd.Flags().StringVar(&evalFlag, "evaluation-time", "", "override snapshot evaluation_time (RFC3339)")
	cmd.Flags().StringVar(&kbFlag, "kb-version", "", "override snapshot kb_version; not allowed with --kb")
	cmd.Flags().StringVar(&maxKBAge, "max-kb-age", "", "with --kb: refuse a bundle created more than this long before the evaluation time (a bundle newer than the snapshot is allowed unless it is in the future) (Go duration, or Nd for days, e.g. 30d)")
	cmd.Flags().BoolVar(&allowOlderKB, "allow-older-kb", false, "with --kb: accept a version older than the one named in the knowledge-base LATEST file")
	addMaxSnapshotBytes(cmd, &maxSnap)
	cmd.Flags().StringVar(&asset, "asset", "", "evaluate a single asset id")
	return cmd
}

func loadFallback(paths []string, cve string, port int, proto string) (*osv.Build, error) {
	var recs []osv.Record
	var raws [][]byte
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		rs, err := osv.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		recs = append(recs, rs...)
		raws = append(raws, raw)
	}
	if cve == "" {
		var err error
		cve, err = osv.CVEOf(recs)
		if err != nil {
			return nil, err
		}
	}
	return osv.BuildPack(recs, cve, raws, port, proto)
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

// parseAge reads a Go duration or a whole number of days ("30d").
func parseAge(s string) (time.Duration, error) {
	var d time.Duration
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 1 || days > 36500 {
			return 0, fmt.Errorf("%q is not a positive number of days", s)
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, err
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("%q must be positive", s)
	}
	return d, nil
}

// kbClockSkew is how far past the wall clock a bundle's created_at may be.
const kbClockSkew = 5 * time.Minute

// checkKBAge refuses a bundle created after now+kbClockSkew (a forged or
// mis-set clock) and, when maxAge is set, one created more than maxAge before
// the evaluation time. A bundle created after the evaluation time but not in
// the future is allowed (re-checking an older snapshot with newer knowledge);
// newer reports that case.
func checkKBAge(createdAt string, evalAt, now time.Time, maxAge time.Duration) (newer bool, err error) {
	at, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return false, fmt.Errorf("bundle created_at: %w", err)
	}
	if at.After(now.Add(kbClockSkew)) {
		return false, fmt.Errorf("bundle created_at %s is in the future (now %s, allowed skew %s); the bundle or this machine's clock is wrong", createdAt, now.UTC().Format(time.RFC3339), kbClockSkew)
	}
	if maxAge > 0 && at.Before(evalAt.Add(-maxAge)) {
		return false, fmt.Errorf("bundle created_at %s is older than --max-kb-age %s before evaluation_time %s; install a newer bundle", createdAt, maxAge, evalAt.UTC().Format(time.RFC3339))
	}
	return at.After(evalAt), nil
}
