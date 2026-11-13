// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/canonjson"
	"github.com/uddeshya-world/verdict/internal/importer"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// maxEditsFileBytes bounds a batch edits file.
const maxEditsFileBytes = 16 << 20

// editFile is the schema of `snapshot apply --file`.
type editFile struct {
	Edits []fileEdit `json:"edits"`
}

// fileEdit is one batch operation. evidence_file is resolved against the
// directory of the edits file and hashed.
type fileEdit struct {
	snapshot.Edit
	EvidenceFile string `json:"evidence_file,omitempty"`
}

func (f *fileEdit) UnmarshalJSON(b []byte) error {
	type alias struct {
		snapshot.Edit
		EvidenceFile string `json:"evidence_file,omitempty"`
	}
	var a alias
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return err
	}
	f.Edit, f.EvidenceFile = a.Edit, a.EvidenceFile
	return nil
}

// evidenceID returns "sha256:" plus the hex digest of the file's bytes.
func evidenceID(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("evidence %s is not a regular file", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return snapshot.EvidenceIDPrefix + hex.EncodeToString(h.Sum(nil)), nil
}

func attachEvidence(e *snapshot.Edit, path string) error {
	if path == "" {
		return nil
	}
	id, err := evidenceID(path)
	if err != nil {
		return fmt.Errorf("evidence file: %w", err)
	}
	e.EvidenceID, e.HasEvidence = id, true
	return nil
}

// runEdits loads in, applies edits atomically, and writes out.
func runEdits(stdout io.Writer, in, out string, maxBytes int64, edits []snapshot.Edit, label string, asJSON bool) error {
	if in == "" || out == "" {
		return &ExitError{Code: 2, Err: fmt.Errorf("--snapshot and --out are required")}
	}
	s, err := loadSnapshotFile(in, maxBytes)
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	got, err := snapshot.Apply(s, edits, importer.ValidateHostFact, maxBytes)
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	body, err := canonjson.Marshal(got)
	if err != nil {
		return err
	}
	if err := writeSnapshot(out, body, maxBytes); err != nil {
		return err
	}
	if asJSON {
		return writeJSON(stdout, snapshotResult{Command: "snapshot " + label, OK: true, Out: out, Edits: len(edits), Assets: len(got.Assets)})
	}
	fmt.Fprintf(stdout, "snapshot %s: edits=%d assets=%d\n", label, len(edits), len(got.Assets))
	return nil
}

const basisHelp = `Basis is attested (default) or observed. An attested entry can never reach
the not_affected bar, whatever its confidence. observed needs --evidence FILE
(its SHA-256 becomes the evidence id) and --observed-at; verdict cannot check
that the file proves the claim, so the entry is still caller-asserted. Confidence
is low or medium (default); high needs basis observed. An existing entry is
never overwritten without --replace. observed-at defaults to the snapshot's
evaluation_time for attested entries (the clock is not read).`

func newSnapshotSetFact(stdout io.Writer) *cobra.Command {
	var in, out, evidence string
	var maxBytes int64
	var asJSON bool
	e := snapshot.Edit{Op: snapshot.OpSetFact}
	cmd := &cobra.Command{
		Use:   "set-fact",
		Short: "Add or replace one host fact on one asset",
		Long:  "Add one fact to one asset of a snapshot and write a new snapshot.\n" + basisHelp,
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := attachEvidence(&e, evidence); err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			return runEdits(stdout, in, out, maxBytes, []snapshot.Edit{e}, "set-fact", asJSON)
		},
	}
	f := cmd.Flags()
	f.StringVar(&in, "snapshot", "", "snapshot JSON to read")
	f.StringVar(&out, "out", "", "snapshot JSON to write")
	f.StringVar(&e.Asset, "asset", "", "asset id")
	f.StringVar(&e.Key, "key", "", "fact key, for example libc.family")
	f.StringVar(&e.Value, "value", "", "fact value")
	f.StringVar(&e.PURL, "purl", "", "limit the fact to this inventory package")
	f.StringVar(&e.Basis, "basis", "attested", "attested or observed")
	f.StringVar(&e.Confidence, "confidence", "medium", "low, medium, or high (high needs --basis observed)")
	f.StringVar(&e.ObservedAt, "observed-at", "", "RFC3339 time of observation (required for observed)")
	f.StringVar(&e.ExpiresAt, "expires-at", "", "RFC3339 time after which the fact is unusable")
	f.StringVar(&evidence, "evidence", "", "evidence file; its SHA-256 becomes the evidence id")
	f.StringVar(&e.Source, "source", "", "free-text origin of the fact")
	f.BoolVar(&e.Replace, "replace", false, "overwrite an existing fact with the same key and package")
	addMaxSnapshotBytes(cmd, &maxBytes)
	addJSONFlag(cmd, &asJSON)
	return cmd
}

func newSnapshotSetExposure(stdout io.Writer) *cobra.Command {
	var in, out, evidence string
	var maxBytes int64
	var asJSON bool
	e := snapshot.Edit{Op: snapshot.OpSetExposure}
	cmd := &cobra.Command{
		Use:   "set-exposure",
		Short: "Add or widen the zones that reach one port of one asset",
		Long: "Record which zones reach a port. Without --replace this only adds a port or\n" +
			"widens its zones: --reachable-from must list every zone already recorded for that\n" +
			"port and protocol. Narrowing or removing a zone needs --replace.\n" + basisHelp,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := attachEvidence(&e, evidence); err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			return runEdits(stdout, in, out, maxBytes, []snapshot.Edit{e}, "set-exposure", asJSON)
		},
	}
	f := cmd.Flags()
	f.StringVar(&in, "snapshot", "", "snapshot JSON to read")
	f.StringVar(&out, "out", "", "snapshot JSON to write")
	f.StringVar(&e.Asset, "asset", "", "asset id")
	f.IntVar(&e.Port, "port", 0, "port number")
	f.StringVar(&e.Proto, "proto", "", "tcp or udp")
	f.StringSliceVar(&e.ReachableFrom, "reachable-from", nil, "zone that reaches the port; comma-separated or repeated")
	f.StringVar(&e.Basis, "basis", "attested", "attested or observed")
	f.StringVar(&e.Confidence, "confidence", "medium", "low, medium, or high (high needs --basis observed)")
	f.StringVar(&e.ObservedAt, "observed-at", "", "RFC3339 time of observation (required for observed)")
	f.StringVar(&e.ExpiresAt, "expires-at", "", "RFC3339 time after which the entry is unusable")
	f.StringVar(&evidence, "evidence", "", "evidence file; its SHA-256 becomes the evidence id")
	f.StringVar(&e.Source, "source", "", "free-text origin of the entry")
	f.BoolVar(&e.Replace, "replace", false, "allow narrowing or removing zones for this port")
	addMaxSnapshotBytes(cmd, &maxBytes)
	addJSONFlag(cmd, &asJSON)
	return cmd
}

func newSnapshotApply(stdout io.Writer) *cobra.Command {
	var in, out, file string
	var maxBytes int64
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a file of set-fact / set-exposure edits atomically",
		Long: "Apply every edit in --file, in order, or none: the first failing edit aborts the run\n" +
			"and nothing is written. Each edit follows the same rules as the single commands.\n" +
			"evidence_file paths are relative to the edits file.\n" + basisHelp,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if file == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--file is required")}
			}
			edits, err := loadEditFile(file)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			return runEdits(stdout, in, out, maxBytes, edits, "apply", asJSON)
		},
	}
	cmd.Flags().StringVar(&in, "snapshot", "", "snapshot JSON to read")
	cmd.Flags().StringVar(&out, "out", "", "snapshot JSON to write")
	cmd.Flags().StringVar(&file, "file", "", "edits JSON: {\"edits\":[{\"op\":\"set_fact\",...}]}")
	addMaxSnapshotBytes(cmd, &maxBytes)
	addJSONFlag(cmd, &asJSON)
	return cmd
}

func loadEditFile(path string) ([]snapshot.Edit, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxEditsFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxEditsFileBytes {
		return nil, fmt.Errorf("%s: edits file is over %d bytes", path, maxEditsFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var ef editFile
	if err := dec.Decode(&ef); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: trailing JSON", path)
	}
	dir := filepath.Dir(path)
	edits := make([]snapshot.Edit, 0, len(ef.Edits))
	for i := range ef.Edits {
		e := ef.Edits[i].Edit
		if p := ef.Edits[i].EvidenceFile; p != "" {
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			if err := attachEvidence(&e, p); err != nil {
				return nil, fmt.Errorf("edit %d: %w", i+1, err)
			}
		}
		edits = append(edits, e)
	}
	return edits, nil
}
