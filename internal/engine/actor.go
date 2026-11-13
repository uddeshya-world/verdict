// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/uddeshya-world/verdict/internal/purl"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// agentDowngrade returns a copy of asset in which every fact and exposure
// entry whose most recent edit record names an agent has basis observed
// replaced by attested, and the evidence ids of the facts it downgraded.
// The snapshot edit commands already refuse an agent entering observed; this
// covers a hand-written snapshot. It can only take an observation away, so it
// can only make not_affected harder. Records without actor_kind are human.
// The caller's asset is not modified.
func agentDowngrade(asset snapshot.Asset) (snapshot.Asset, map[string]bool) {
	if len(asset.Edits) == 0 {
		return asset, nil
	}
	var downgraded map[string]bool
	factAgent := func(f snapshot.Fact) bool {
		last := -1
		for i, e := range asset.Edits {
			if e.Op == snapshot.OpSetFact && e.Key == f.Key && samePURL(e.PURL, f.PURL) {
				last = i
			}
		}
		return last >= 0 && asset.Edits[last].IsAgent()
	}
	expAgent := func(x snapshot.Exposure) bool {
		last := -1
		for i, e := range asset.Edits {
			if e.Op == snapshot.OpSetExposure && e.Port == x.Port && e.Proto == x.Proto {
				last = i
			}
		}
		return last >= 0 && asset.Edits[last].IsAgent()
	}
	facts := asset.Facts
	for i, f := range asset.Facts {
		if f.Basis != "observed" || !factAgent(f) {
			continue
		}
		if downgraded == nil {
			facts = append([]snapshot.Fact{}, asset.Facts...)
			downgraded = map[string]bool{}
		}
		facts[i].Basis = "attested"
		downgraded[f.EvidenceID] = true
	}
	exposure := asset.Exposure
	copied := false
	for i, x := range asset.Exposure {
		if x.Basis != "observed" || !expAgent(x) {
			continue
		}
		if !copied {
			exposure = append([]snapshot.Exposure{}, asset.Exposure...)
			copied = true
		}
		exposure[i].Basis = "attested"
	}
	asset.Facts, asset.Exposure = facts, exposure
	return asset, downgraded
}

func samePURL(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	return a == b || purl.Same(a, b)
}
