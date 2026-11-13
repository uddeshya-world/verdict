// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"strings"
	"time"

	"github.com/uddeshya-world/verdict/internal/factkeys"
	"github.com/uddeshya-world/verdict/internal/logic"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/policy"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func classifyExposure(pol *policy.Policy, spec pack.ExposureSpec, asset snapshot.Asset, eval time.Time, maxAge time.Duration) ExposureClass {
	if pol == nil {
		return ExposureClass{Kind: "unknown", Uncertain: true, Reason: "zone_policy_missing"}
	}
	if spec.PortFact == "" {
		return classifyPort(pol, spec.Port, spec.Proto, asset, eval, maxAge)
	}
	ports, portEvidence, reason := exposurePorts(spec.PortFact, asset, eval, maxAge)
	if reason != "" {
		return ExposureClass{Kind: "unknown", Uncertain: true, Reason: reason, EvidenceIDs: uniq(portEvidence)}
	}
	// The asset is exposed if any listening port is exposed or unknown.
	// trusted_only needs every port to be trusted_only.
	evidence := append([]string{}, portEvidence...)
	sawUntrusted, sawUnknown := false, false
	for _, port := range ports {
		c := classifyPort(pol, port, spec.Proto, asset, eval, maxAge)
		evidence = append(evidence, c.EvidenceIDs...)
		switch c.Kind {
		case "untrusted":
			sawUntrusted = true
		case "trusted_only":
		default:
			sawUnknown = true
		}
	}
	switch {
	case sawUntrusted:
		return ExposureClass{Kind: "untrusted", EvidenceIDs: uniq(evidence)}
	case sawUnknown:
		return ExposureClass{Kind: "unknown", Uncertain: true, EvidenceIDs: uniq(evidence)}
	}
	return ExposureClass{Kind: "trusted_only", EvidenceIDs: uniq(evidence)}
}

// exposurePorts reads the port list a pack's exposure.port_fact names. Any
// problem is a reason, and the caller treats exposure as unknown. There is no
// fallback port. The fact must be one unscoped fact under the exact key, with
// a canonical value (factkeys.ParsePortList), and must meet the same bar as
// exposure evidence: observed, high confidence or better, fresh, unexpired.
func exposurePorts(key string, asset snapshot.Asset, eval time.Time, maxAge time.Duration) ([]int, []string, string) {
	var found []*snapshot.Fact
	for i := range asset.Facts {
		f := &asset.Facts[i]
		if f.Key == key || foldKey(f.Key) == foldKey(key) {
			found = append(found, f)
		}
	}
	var ev []string
	for _, f := range found {
		ev = append(ev, f.EvidenceID)
	}
	if len(found) == 0 {
		return nil, nil, "exposure_port_unobserved"
	}
	// A case variant of the key, a purl-scoped copy, or two facts are not one
	// observation of the listening ports.
	if len(found) != 1 || found[0].Key != key || found[0].PURL != "" {
		return nil, ev, "exposure_port_not_canonical"
	}
	f := found[0]
	ok, observed, conf, _ := assess(observation{
		Basis: f.Basis, Confidence: f.Confidence, ObservedAt: f.ObservedAt, ExpiresAt: f.ExpiresAt,
	}, eval, maxAge)
	if !ok || !observed || conf < logic.ConfHigh {
		return nil, ev, "exposure_port_evidence_insufficient"
	}
	ports, err := factkeys.ParsePortList(f.Value)
	if err != nil {
		return nil, ev, "exposure_port_not_canonical"
	}
	return ports, ev, ""
}

// classifyPort classifies one port from the asset's exposure observations.
func classifyPort(pol *policy.Policy, port int, proto string, asset snapshot.Asset, eval time.Time, maxAge time.Duration) ExposureClass {
	untrustedZones := zoneSet(pol.UntrustedZones)
	trustedZones := zoneSet(pol.TrustedZones)
	var evidence []string
	sawUntrusted := false
	sawUnknown := false
	usable := 0
	for _, e := range asset.Exposure {
		if e.Port != port || e.Proto != proto {
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
