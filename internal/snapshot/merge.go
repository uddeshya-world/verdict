// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package snapshot

import (
	"encoding/json"
	"fmt"
)

// Merge concatenates assets from snapshots that share the same evaluation
// time, knowledge-bundle version, and evidence trust. Duplicate asset ids
// are rejected. The result is loaded again so it cannot skip validation.
func Merge(parts ...*Snapshot) (*Snapshot, error) {
	if len(parts) < 2 {
		return nil, fmt.Errorf("snapshot merge: at least two snapshots are required")
	}
	base := parts[0]
	if base == nil {
		return nil, fmt.Errorf("snapshot merge: snapshot is nil")
	}
	var assets []Asset
	seen := map[string]struct{}{}
	for i, s := range parts {
		if s == nil {
			return nil, fmt.Errorf("snapshot merge: snapshot %d is nil", i)
		}
		if s.KBVersion != base.KBVersion || s.EvaluationTime != base.EvaluationTime || s.EvidenceTrust != base.EvidenceTrust {
			return nil, fmt.Errorf("snapshot merge: snapshot %d does not match kb_version, evaluation_time, and evidence_trust", i)
		}
		for _, a := range s.Assets {
			if _, ok := seen[a.ID]; ok {
				return nil, fmt.Errorf("snapshot merge: duplicate asset %q", a.ID)
			}
			seen[a.ID] = struct{}{}
			assets = append(assets, a)
		}
	}
	out := &Snapshot{
		KBVersion: base.KBVersion, EvaluationTime: base.EvaluationTime,
		EvidenceTrust: base.EvidenceTrust, Assets: assets,
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	// The parts were already loaded under the caller's cap, so the merged
	// document is re-validated at its own size. The caller caps the output.
	return LoadMax(raw, int64(len(raw)))
}
