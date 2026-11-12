// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/uddeshya-world/verdict/internal/purl"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// AdvisoryOptions controls how advisory rows that match no package are handled.
type AdvisoryOptions struct {
	// AllowUnmatched drops a row that matches no inventory package and
	// reports it, instead of failing the import. A dropped row is not written.
	AllowUnmatched bool
}

// AdvisoryReport says where each advisory row landed.
type AdvisoryReport struct {
	// Matched has one line per row: the row purl and the inventory purls it was written to.
	Matched []string
	// Unmatched lists rows that matched no package on their asset.
	Unmatched []string
	// Facts is the number of facts written.
	Facts int
}

// ApplyAdvisories writes advisory facts onto the inventory packages they name.
//
// A row is written to every package on its asset with the same canonical
// type, namespace, name, and version, where an rpm/deb epoch may be given in
// the version or in the epoch qualifier. The arch and upstream qualifiers are
// ignored on both sides. A distro qualifier on the row must equal the
// package's; a row without one does not constrain distro, so a row for
// ubuntu-22.04 never lands on an ubuntu-24.04 package. Any other qualifier
// and the subpath must be equal. The fact carries the package's exact purl.
//
// A row that matches nothing is an error unless opt.AllowUnmatched is set.
// Two rows with the same key and different values on one package are an
// error. The importer never invents a status for a package that is not named.
func ApplyAdvisories(s *snapshot.Snapshot, doc *AdvisoryDocument, opt AdvisoryOptions) (*snapshot.Snapshot, *AdvisoryReport, error) {
	if s == nil || doc == nil {
		return nil, nil, fmt.Errorf("import advisories: snapshot and document are required")
	}
	next := *s
	next.Assets = append([]snapshot.Asset{}, s.Assets...)
	index := map[string]int{}
	for i := range next.Assets {
		index[next.Assets[i].ID] = i
	}
	rep := &AdvisoryReport{}
	for _, f := range doc.Facts {
		i, ok := index[f.AssetID]
		if !ok {
			return nil, nil, fmt.Errorf("import advisories: asset %q is not in the snapshot", f.AssetID)
		}
		asset := next.Assets[i]
		canon, err := purl.Canonical(f.PURL)
		if err != nil {
			return nil, nil, fmt.Errorf("import advisories: %s: %w", f.Key, err)
		}
		rowKey, err := parseKey(canon)
		if err != nil {
			return nil, nil, fmt.Errorf("import advisories: %s: %w", f.Key, err)
		}
		targets := matchInventory(asset, rowKey)
		if len(targets) == 0 {
			rep.Unmatched = append(rep.Unmatched, fmt.Sprintf("asset %s key %s purl %s", f.AssetID, f.Key, canon))
			continue
		}
		facts := append([]snapshot.Fact{}, asset.Facts...)
		for _, target := range targets {
			dup := false
			for _, have := range facts {
				if have.Key != f.Key || !purl.Same(have.PURL, target) {
					continue
				}
				if have.Value != f.Value {
					return nil, nil, fmt.Errorf("import advisories: asset %s purl %s: %s is both %s and %s", f.AssetID, target, f.Key, have.Value, f.Value)
				}
				dup = true
			}
			if dup {
				continue
			}
			facts = append(facts, snapshot.Fact{
				Key: f.Key, PURL: target, Value: f.Value, Basis: f.Basis, Confidence: f.Confidence,
				ObservedAt: f.ObservedAt, ExpiresAt: f.ExpiresAt, EvidenceID: f.EvidenceID, Source: f.Source,
			})
			rep.Facts++
		}
		asset.Facts = facts
		next.Assets[i] = asset
		rep.Matched = append(rep.Matched, fmt.Sprintf("asset %s purl %s -> %s", f.AssetID, canon, strings.Join(targets, ", ")))
	}
	if len(rep.Unmatched) > 0 && !opt.AllowUnmatched {
		return nil, rep, fmt.Errorf("import advisories: %d of %d rows match no inventory package (%s); fix the purl or pass --allow-unmatched", len(rep.Unmatched), len(doc.Facts), strings.Join(rep.Unmatched, "; "))
	}
	raw, err := json.Marshal(&next)
	if err != nil {
		return nil, nil, err
	}
	checked, err := snapshot.Load(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("import advisories: %w", err)
	}
	return checked, rep, nil
}

func matchInventory(asset snapshot.Asset, row purlKey) []string {
	var out []string
	for _, pkg := range asset.Inventory.Packages {
		canon, err := purl.Canonical(pkg.PURL)
		if err != nil {
			continue
		}
		k, err := parseKey(canon)
		if err != nil {
			continue
		}
		if row.matches(k) {
			out = append(out, canon)
		}
	}
	sort.Strings(out)
	return out
}

// purlKey is a canonical package URL split for advisory matching.
type purlKey struct {
	typ, namespace, name string
	// evr is the version with an rpm/deb epoch qualifier folded in and a
	// zero epoch removed.
	evr     string
	distro  string
	hasDist bool
	// other holds every qualifier except arch, upstream, epoch, and distro,
	// in canonical order.
	other   string
	subpath string
}

func (row purlKey) matches(pkg purlKey) bool {
	if row.typ != pkg.typ || row.namespace != pkg.namespace || row.name != pkg.name {
		return false
	}
	if row.evr == "" || row.evr != pkg.evr {
		return false
	}
	if row.other != pkg.other || row.subpath != pkg.subpath {
		return false
	}
	if row.hasDist && (!pkg.hasDist || row.distro != pkg.distro) {
		return false
	}
	return true
}

// parseKey splits a canonical package URL. canon must come from purl.Canonical.
func parseKey(canon string) (purlKey, error) {
	parsed, err := purl.Parse(canon)
	if err != nil {
		return purlKey{}, err
	}
	k := purlKey{typ: parsed.Type, namespace: parsed.Namespace, name: parsed.Name}
	rest := strings.TrimPrefix(canon, "pkg:")
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		k.subpath = rest[i+1:]
		rest = rest[:i]
	}
	qual := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		qual = rest[i+1:]
	}
	version, err := purl.Decode(parsed.Version)
	if err != nil {
		return purlKey{}, err
	}
	epoch := ""
	var other []string
	if qual != "" {
		for _, item := range strings.Split(qual, "&") {
			name, value, _ := strings.Cut(item, "=")
			switch name {
			case "arch", "upstream":
			case "epoch":
				if !epochAware(k.typ) {
					other = append(other, item)
					continue
				}
				epoch, err = purl.Decode(value)
				if err != nil {
					return purlKey{}, err
				}
			case "distro":
				k.hasDist = true
				k.distro, err = purl.Decode(value)
				if err != nil {
					return purlKey{}, err
				}
			default:
				other = append(other, item)
			}
		}
	}
	k.other = strings.Join(other, "&")
	if version == "" {
		return k, nil
	}
	if epochAware(k.typ) {
		if epoch != "" {
			if e, v, ok := strings.Cut(version, ":"); ok {
				if foldEpoch(e+":") != foldEpoch(epoch+":") {
					return purlKey{}, fmt.Errorf("purl: epoch qualifier %q disagrees with version %q", epoch, version)
				}
				version = v
			}
			version = epoch + ":" + version
		}
		version = foldEpoch(version)
	}
	k.evr = version
	return k, nil
}

// epochAware reports whether a type's versions carry an epoch.
func epochAware(typ string) bool {
	return typ == "rpm" || typ == "deb"
}

// foldEpoch removes an explicit zero epoch, which rpm and dpkg treat as no epoch.
func foldEpoch(v string) string {
	if strings.HasPrefix(v, "0:") {
		return v[2:]
	}
	return v
}
