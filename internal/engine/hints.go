// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import "fmt"

func leafHint(reason, checkID, detail, packHint string) string {
	var base string
	switch reason {
	case "missing_fact":
		base = fmt.Sprintf("Check %s needs fact %q in the snapshot with basis observed or attested, a confidence, and observed_at within the pack evidence_max_age of evaluation_time. v0.1 does not collect this fact and does not fill in a vendor default when the key is absent.", checkID, detail)
	case "stale_evidence":
		base = fmt.Sprintf("Evidence for check %s is older than evidence_max_age at the explicit evaluation time. Re-collect it. Stale evidence is unknown, not a proof of not_affected.", checkID)
	case "expired_evidence":
		base = fmt.Sprintf("Evidence for check %s expires at or before the evaluation time. Replace it. Expired evidence is unknown.", checkID)
	case "evidence_time_after_evaluation":
		base = fmt.Sprintf("Evidence for check %s is timestamped after the evaluation time, so this run cannot use it.", checkID)
	case "inferred_evidence_discarded":
		base = fmt.Sprintf("Check %s has basis inferred. Inferred values are discarded and cannot falsify a precondition.", checkID)
	case "evidence_not_observed":
		base = fmt.Sprintf("Check %s is not basis observed. Attestations can support an affected result and cannot support not_affected.", checkID)
	case "confidence_below_not_affected_bar":
		base = fmt.Sprintf("Check %s is below high confidence. Raising the number in JSON does not authenticate it, and a low value cannot support not_affected.", checkID)
	case "inventory_incomplete":
		base = fmt.Sprintf("Inventory for check %s is not marked complete, so a missing package is not component_not_present.", checkID)
	case "inventory_not_observed":
		base = fmt.Sprintf("Inventory for check %s is not a fresh observed list, so package absence or version order cannot be used.", checkID)
	case "distro_advisory_required":
		base = fmt.Sprintf("Check %s cannot treat %s as not-vulnerable by sorting versions. A deb, rpm, or apk build, or the same component name under a different package type, needs a fresh observed advisory fact (affected or fixed) or the result stays unknown.", checkID, detail)
	case "unsupported_version":
		base = fmt.Sprintf("Check %s could not parse a version with the pack scheme. Unparsed versions are unknown, not outside the vulnerable range.", checkID)
	case "unexpected_advisory_value":
		base = fmt.Sprintf("Advisory fact %q must be exactly affected or fixed.", detail)
	case "advisory_without_package":
		base = fmt.Sprintf("Advisory fact %q is present but no matching package is in the inventory, so the advisory was not applied.", detail)
	case "advisory_not_observed":
		base = fmt.Sprintf("Advisory fact %q is not fresh observed evidence, and the engine did not fall through to version sorting.", detail)
	case "attestation_missing_expiry":
		base = fmt.Sprintf("Check %s is a manual attestation and needs expires_at. An attestation without an expiry is unknown.", checkID)
	case "malformed_purl":
		base = fmt.Sprintf("Check %s found a package URL it could not parse. That coordinate is unknown.", checkID)
	case "version_purl_mismatch":
		base = fmt.Sprintf("Check %s found a package whose version field disagrees with the version in the package URL.", checkID)
	case "unexpected_fact_value":
		base = fmt.Sprintf("Check %s expected fact %q to be true or false.", checkID, detail)
	case "when_package_unresolved":
		base = fmt.Sprintf("Check %s is gated on a package version and that version could not be resolved. The mitigation was not treated as present or as proof of not_affected.", checkID)
	case "when_package_not_applicable":
		base = fmt.Sprintf("Check %s does not apply at the observed package version, so the predicate is false. When this check sits under not, the mitigation is not in effect. That is not proof of not_affected.", checkID)
	default:
		base = fmt.Sprintf("Check %s is unresolved (%s).", checkID, reason)
	}
	if packHint != "" {
		return base + " Pack hint: " + packHint
	}
	return base
}

func decisionHint(reason string) string {
	switch reason {
	case "pack_not_reviewed":
		return "Pack status is not reviewed. Draft packs cannot produce not_affected, even when a sufficient proof of a falsified precondition exists. Reviewers are not invented to clear this."
	case "reviewer_quorum_not_met":
		return "not_affected requires two distinct reviewer names on a reviewed pack. This pack does not meet that bar."
	case "pack_deprecated":
		return "The pack is deprecated. not_affected was withheld."
	case "confidence_ceiling_blocks_not_affected":
		return "The pack confidence ceiling is below high, so not_affected is impossible."
	case "confidence_below_not_affected_bar":
		return "After the pack ceiling, the falsifying proof is below high confidence. not_affected was withheld."
	case "mixed_justification":
		return "The sufficient proof uses more than one OpenVEX justification. not_affected was withheld instead of publishing a single label the proof does not uniformly support."
	case "insufficient_proof":
		return "There is no sufficient observed high-confidence proof that a required precondition is false."
	case "tree_unknown":
		return "The condition tree is unknown. Unknown, including a single unknown branch of a disjunction, does not become not_affected."
	case "tree_false_without_sufficient_proof":
		return "The condition tree is false, but the falsifying evidence is not a complete observed high-confidence proof."
	case "exposure_unknown_treated_as_exposed":
		return "Exposure for this affected asset is not a fresh high-confidence observation whose zones are all listed in trusted_zones. A missing, stale, inferred, or low-confidence record, or a zone in neither trusted_zones nor untrusted_zones, is exploitable with exposure_uncertainty. Matching is case-insensitive. Asset zone labels are not exposure evidence. A path that is only in trusted_zones stays affected as vulnerable_not_exposed."
	default:
		return reason
	}
}
