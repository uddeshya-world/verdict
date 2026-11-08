// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"strings"
	"time"

	"github.com/uddeshya-world/verdict/internal/logic"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func classifyExposure(spec pack.ExposureSpec, asset snapshot.Asset, eval time.Time, maxAge time.Duration) ExposureClass {
	var evidence []string
	sawUntrusted := false
	sawUnknown := false
	usable := 0
	for _, e := range asset.Exposure {
		if e.Port != spec.Port || e.Proto != spec.Proto {
			continue
		}
		ok, observed, conf, _ := assess(observation{
			Basis: e.Basis, Confidence: e.Confidence, ObservedAt: e.ObservedAt, ExpiresAt: e.ExpiresAt,
		}, eval, maxAge)
		if !ok || !observed || conf < logic.ConfHigh {
			continue
		}
		usable++
		evidence = append(evidence, e.EvidenceID)
		untrusted, unknownZone := false, false
		if len(e.ReachableFrom) == 0 {
			unknownZone = true
		}
		for _, z := range e.ReachableFrom {
			if z == "" || strings.EqualFold(z, "unknown") {
				unknownZone = true
			}
			for _, u := range spec.UntrustedZones {
				if z == u {
					untrusted = true
				}
			}
		}
		if untrusted {
			sawUntrusted = true
		}
		if unknownZone {
			sawUnknown = true
		}
	}
	if usable == 0 || sawUnknown && !sawUntrusted {
		return ExposureClass{Kind: "unknown", Uncertain: true, EvidenceIDs: uniq(evidence)}
	}
	if sawUntrusted {
		return ExposureClass{Kind: "untrusted", EvidenceIDs: uniq(evidence)}
	}
	return ExposureClass{Kind: "trusted_only", EvidenceIDs: uniq(evidence)}
}
