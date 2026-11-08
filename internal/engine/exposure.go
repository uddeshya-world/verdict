// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"strings"
	"time"

	"github.com/uddeshya-world/verdict/internal/logic"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/policy"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func classifyExposure(pol *policy.Policy, spec pack.ExposureSpec, asset snapshot.Asset, eval time.Time, maxAge time.Duration) ExposureClass {
	if pol == nil {
		return ExposureClass{Kind: "unknown", Uncertain: true, Reason: "zone_policy_missing"}
	}
	untrustedZones := zoneSet(pol.UntrustedZones)
	trustedZones := zoneSet(pol.TrustedZones)
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
			key := strings.ToLower(z)
			switch {
			case z == "" || key == "unknown":
				unknownZone = true
			case zoneListed(untrustedZones, key):
				untrusted = true
			case zoneListed(trustedZones, key):
			default:
				// A label in neither list is not trusted. Typos and
				// unexpected case-sensitive leftovers fail closed.
				unknownZone = true
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

func zoneSet(zones []string) map[string]struct{} {
	out := make(map[string]struct{}, len(zones))
	for _, z := range zones {
		out[strings.ToLower(z)] = struct{}{}
	}
	return out
}

func zoneListed(set map[string]struct{}, key string) bool {
	_, ok := set[key]
	return ok
}
