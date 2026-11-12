// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/uddeshya-world/verdict/internal/factkeys"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// HostSchema is the schema string scripts/collect-host.sh writes.
const HostSchema = "verdict.collect-host/v1"

// HostSource is the source recorded on facts from a host document.
const HostSource = "collect-host.sh"

// HostMaxBytes is the largest collector document accepted.
const HostMaxBytes = 16 * 1024 * 1024

// HostOptions is how a collect-host.sh document becomes one asset.
// Basis and confidence are not options: the collector read the values
// itself, so they are observed and high. The document is still caller-asserted.
type HostOptions struct {
	AssetID   string
	AssetName string
	AssetKind string
	Zones     []string
	Complete  bool
	// ReachableFrom is the operator's statement of which zones reach the
	// listening ports. Empty means no exposure is written.
	ReachableFrom []string
	KBVersion     string
	Evaluation    string
}

type hostDoc struct {
	Schema      string `json:"schema"`
	Collector   string `json:"collector"`
	Hostname    string `json:"hostname"`
	CollectedAt string `json:"collected_at"`
	OS          struct {
		ID        string `json:"id"`
		VersionID string `json:"version_id"`
	} `json:"os"`
	Packages []struct {
		Manager string `json:"manager"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"packages"`
	Unparsed []struct {
		Manager string `json:"manager"`
		Line    string `json:"line"`
	} `json:"unparsed"`
	Facts     map[string]string `json:"facts"`
	Listening *[]struct {
		Port    int    `json:"port"`
		Proto   string `json:"proto"`
		Process string `json:"process"`
	} `json:"listening"`
	Notes []string `json:"notes"`
}

// hostFacts is every key the collector may write and how its value is checked.
// A key outside this list is malformed input, not something to pass through.
var hostFacts = map[string]func(string) (string, error){
	"config.sshd.LoginGraceTime": sshdSeconds,
}

func init() {
	for k, allowed := range factkeys.Closed {
		hostFacts[k] = oneOf(allowed...)
	}
}

// Host reads one collect-host.sh JSON document into one asset.
// A fact the collector omitted stays absent. Listening ports become
// exposure only when opt.ReachableFrom is set. Result.Notes holds the
// collector's own notes, which are untrusted text, then import warnings.
func Host(data []byte, opt HostOptions) (*Result, error) {
	if len(data) > HostMaxBytes {
		return nil, fmt.Errorf("import host: document exceeds %d bytes", HostMaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc hostDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("import host: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("import host: trailing JSON")
	}
	if doc.Schema != HostSchema {
		return nil, fmt.Errorf("import host: schema must be %q (got %q)", HostSchema, doc.Schema)
	}
	if doc.Collector != HostSource {
		return nil, fmt.Errorf("import host: collector must be %q (got %q)", HostSource, doc.Collector)
	}
	collected, err := time.Parse(time.RFC3339, doc.CollectedAt)
	if err != nil {
		return nil, fmt.Errorf("import host: collected_at: %w", err)
	}
	observedAt := collected.UTC().Format(time.RFC3339)
	sum := sha256.Sum256(data)
	evidenceID := "e-host-" + hex.EncodeToString(sum[:8])

	name := opt.AssetName
	if name == "" {
		name = doc.Hostname
	}

	var rows []row
	var skipped []string
	for _, p := range doc.Packages {
		if p.PURL == "" {
			label := p.Name
			if label == "" {
				label = "(unnamed)"
			}
			skipped = append(skipped, label+": no purl")
			continue
		}
		rows = append(rows, row{raw: p.PURL, version: p.Version, name: p.Name})
	}
	for _, u := range doc.Unparsed {
		skipped = append(skipped, fmt.Sprintf("%s: unparsed line %q", u.Manager, u.Line))
	}

	facts, err := hostFactList(doc.Facts, observedAt, evidenceID)
	if err != nil {
		return nil, err
	}
	notes := append([]string{}, doc.Notes...)
	exposure, warn, err := hostExposure(doc, opt.ReachableFrom, observedAt, evidenceID)
	if err != nil {
		return nil, err
	}
	notes = append(notes, warn...)

	res, err := finish(rows, skipped, InventoryOptions{
		AssetID: opt.AssetID, AssetName: name, AssetKind: opt.AssetKind, Zones: opt.Zones,
		Complete: opt.Complete, Basis: "observed", Confidence: "high",
		ObservedAt: observedAt, EvidenceID: evidenceID,
		KBVersion: opt.KBVersion, Evaluation: opt.Evaluation,
	}, "host")
	if err != nil {
		return nil, err
	}
	snap := res.Snapshot
	snap.Assets[0].Facts = facts
	snap.Assets[0].Exposure = exposure
	raw, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	checked, err := snapshot.Load(raw)
	if err != nil {
		return nil, fmt.Errorf("import host: %w", err)
	}
	return &Result{Snapshot: checked, Skipped: res.Skipped, Notes: notes}, nil
}

func hostFactList(in map[string]string, observedAt, evidenceID string) ([]snapshot.Fact, error) {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]snapshot.Fact, 0, len(keys))
	for _, k := range keys {
		check, ok := hostFacts[k]
		if !ok {
			return nil, fmt.Errorf("import host: unknown fact %q", k)
		}
		v, err := check(in[k])
		if err != nil {
			return nil, fmt.Errorf("import host: fact %s: %w", k, err)
		}
		out = append(out, snapshot.Fact{
			Key: k, Value: v, Basis: "observed", Confidence: "high",
			ObservedAt: observedAt, EvidenceID: evidenceID, Source: HostSource,
		})
	}
	return out, nil
}

// hostExposure writes one exposure per listening TCP port, and only when the
// operator named the zones that reach the host. Listening alone says nothing
// about who can connect.
func hostExposure(doc hostDoc, reachable []string, observedAt, evidenceID string) ([]snapshot.Exposure, []string, error) {
	var listening []struct {
		Port    int    `json:"port"`
		Proto   string `json:"proto"`
		Process string `json:"process"`
	}
	if doc.Listening != nil {
		listening = *doc.Listening
	}
	ports := map[int]struct{}{}
	for _, l := range listening {
		if l.Port < 1 || l.Port > 65535 || l.Proto != "tcp" {
			return nil, nil, fmt.Errorf("import host: listening entry %d/%q is invalid", l.Port, l.Proto)
		}
		ports[l.Port] = struct{}{}
	}
	if len(reachable) == 0 {
		return []snapshot.Exposure{}, nil, nil
	}
	for _, z := range reachable {
		if z == "" {
			return nil, nil, fmt.Errorf("import host: --reachable-from zone is empty")
		}
	}
	if doc.Listening == nil {
		return []snapshot.Exposure{}, []string{"listening sockets were not observed; no exposure written"}, nil
	}
	sorted := make([]int, 0, len(ports))
	for p := range ports {
		sorted = append(sorted, p)
	}
	sort.Ints(sorted)
	zones := append([]string{}, reachable...)
	sort.Strings(zones)
	out := make([]snapshot.Exposure, 0, len(sorted))
	for _, p := range sorted {
		out = append(out, snapshot.Exposure{
			Port: p, Proto: "tcp", ReachableFrom: zones,
			Basis: "observed", Confidence: "high", ObservedAt: observedAt, EvidenceID: evidenceID,
			Source: HostSource + " listening; reachable_from asserted by operator",
		})
	}
	return out, nil, nil
}

func oneOf(allowed ...string) func(string) (string, error) {
	return func(v string) (string, error) {
		for _, a := range allowed {
			if v == a {
				return v, nil
			}
		}
		return "", fmt.Errorf("value %q is not one of %v", v, allowed)
	}
}

// sshdSeconds converts an sshd time value (120, 2m, 1m30s) to seconds,
// which is what `sshd -T` prints and what packs compare.
func sshdSeconds(v string) (string, error) {
	if v == "" {
		return "", fmt.Errorf("empty time value")
	}
	total := int64(0)
	num := int64(-1)
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= '0' && c <= '9' {
			if num < 0 {
				num = 0
			}
			num = num*10 + int64(c-'0')
			if num > 1<<31 {
				return "", fmt.Errorf("time value %q is too large", v)
			}
			continue
		}
		if num < 0 {
			return "", fmt.Errorf("time value %q is malformed", v)
		}
		var mult int64
		switch c {
		case 's', 'S':
			mult = 1
		case 'm', 'M':
			mult = 60
		case 'h', 'H':
			mult = 3600
		case 'd', 'D':
			mult = 86400
		case 'w', 'W':
			mult = 604800
		default:
			return "", fmt.Errorf("time value %q is malformed", v)
		}
		total += num * mult
		num = -1
	}
	if num >= 0 {
		total += num
	}
	if total > 1<<31 {
		return "", fmt.Errorf("time value %q is too large", v)
	}
	return strconv.FormatInt(total, 10), nil
}

// ValidateHostFact checks a value against the collector's rule for key. known
// is false for a key the collector never writes; its value is not checked here.
func ValidateHostFact(key, value string) (known bool, err error) {
	check, ok := hostFacts[key]
	if !ok {
		return false, nil
	}
	_, err = check(value)
	return true, err
}
