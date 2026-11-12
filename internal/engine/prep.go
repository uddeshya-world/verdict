// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/uddeshya-world/verdict/internal/purl"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// evalCtx caches pure functions of a package URL string and of a pattern
// string for the length of one evaluation, so a fleet of assets that repeat
// the same coordinates pays for canonicalization and name folding once. It
// holds no per-asset state, never changes a result, and is not safe for
// concurrent use.
type evalCtx struct {
	purls map[string]*purlInfo
	pats  map[string]*purl.Pattern
}

func newEvalCtx() *evalCtx {
	return &evalCtx{purls: map[string]*purlInfo{}, pats: map[string]*purl.Pattern{}}
}

// purlInfo is everything the checks derive from one package URL string.
type purlInfo struct {
	raw       string
	canon     string
	canonErr  bool
	parsed    purl.PURL // Parse(canon); valid when !canonErr && !parseErr
	parseErr  bool
	subj      purl.Subject // valid when !canonErr && !parseErr
	fold      string       // purl.FoldKey(raw)
	rawType   string       // type from Parse(raw), "" on error (mustType)
	rawIsDist bool         // purl.DistroType(rawType)
}

func (c *evalCtx) info(raw string) *purlInfo {
	if pi, ok := c.purls[raw]; ok {
		return pi
	}
	pi := &purlInfo{raw: raw, fold: purl.FoldKey(raw)}
	canon, err := purl.Canonical(raw)
	if err != nil {
		pi.canonErr = true
	} else {
		pi.canon = canon
		parsed, perr := purl.Parse(canon)
		if perr != nil {
			pi.parseErr = true
		} else {
			pi.parsed = parsed
			pi.subj = purl.NewSubject(parsed)
		}
	}
	pi.rawType = mustType(raw)
	pi.rawIsDist = purl.DistroType(pi.rawType)
	c.purls[raw] = pi
	return pi
}

func (c *evalCtx) patterns(list []string) []*purl.Pattern {
	out := make([]*purl.Pattern, len(list))
	for i, raw := range list {
		pt, ok := c.pats[raw]
		if !ok {
			v := purl.NewPattern(raw)
			pt = &v
			c.pats[raw] = pt
		}
		out[i] = pt
	}
	return out
}

// sameAs is purl.Same(fact purl, package purl) from cached canonical forms.
func (a *purlInfo) sameAs(b *purlInfo) bool {
	if a.canonErr || b.canonErr {
		return a.raw == b.raw
	}
	return a.canon == b.canon
}

type prepPkg struct {
	snapshot.Package
	info *purlInfo
}

// assetCtx holds the per-asset prepared packages and advisory indexes.
type assetCtx struct {
	ec    *evalCtx
	asset snapshot.Asset
	pkgs  []prepPkg
	ready bool
	adv   map[string]*advIndex
	named map[string]struct{} // fold keys of inventory packages
}

func newAssetCtx(ec *evalCtx, asset snapshot.Asset) *assetCtx {
	return &assetCtx{ec: ec, asset: asset, adv: map[string]*advIndex{}}
}

func (a *assetCtx) packages() []prepPkg {
	if !a.ready {
		a.pkgs = make([]prepPkg, len(a.asset.Inventory.Packages))
		for i, pkg := range a.asset.Inventory.Packages {
			a.pkgs[i] = prepPkg{Package: pkg, info: a.ec.info(pkg.PURL)}
		}
		a.ready = true
	}
	return a.pkgs
}

// advIndex lists the purl-scoped facts for one key, in fact order, with
// maps from fold key and raw string to positions.
type advIndex struct {
	facts  []*snapshot.Fact
	infos  []*purlInfo
	byFold map[string][]int
}

func (a *assetCtx) advIndex(key string) *advIndex {
	if ix, ok := a.adv[key]; ok {
		return ix
	}
	ix := &advIndex{byFold: map[string][]int{}}
	for i := range a.asset.Facts {
		f := &a.asset.Facts[i]
		if f.Key != key || f.PURL == "" {
			continue
		}
		pi := a.ec.info(f.PURL)
		ix.byFold[pi.fold] = append(ix.byFold[pi.fold], len(ix.facts))
		ix.facts = append(ix.facts, f)
		ix.infos = append(ix.infos, pi)
	}
	a.adv[key] = ix
	return ix
}

// findAdvisories is findAdvisories over the asset's fact index. A fact is
// exact when its canonical form equals the package's, a variant when only
// the fold keys agree. Order is fact order.
func (a *assetCtx) findAdvisories(key string, pi *purlInfo) (exact, variants []*snapshot.Fact) {
	if key == "" || pi.raw == "" {
		return nil, nil
	}
	ix := a.advIndex(key)
	for _, i := range ix.byFold[pi.fold] {
		if ix.infos[i].sameAs(pi) {
			exact = append(exact, ix.facts[i])
		} else {
			variants = append(variants, ix.facts[i])
		}
	}
	return exact, variants
}
