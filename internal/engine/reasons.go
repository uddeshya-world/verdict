// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"sort"
	"strconv"
	"strings"
)

// Reason codes. Every reason the engine writes into a report (Verdict.Reasons,
// Hint.Reason, LeafView.Reason, ProofView.SuppressReasons) is one of these
// constants and has an entry in Reasons. reasons_test.go fails the build when
// engine code uses a reason string literal instead of a constant, or when a
// constant has no catalog entry.
const (
	// Leaf reasons: one check after the evidence rules.
	ReasonUnreadableTime                   = "unreadable_time"
	ReasonEvidenceTimeAfterEvaluation      = "evidence_time_after_evaluation"
	ReasonStaleEvidence                    = "stale_evidence"
	ReasonExpiredEvidence                  = "expired_evidence"
	ReasonUnreadableConfidence             = "unreadable_confidence"
	ReasonInferredEvidenceDiscarded        = "inferred_evidence_discarded"
	ReasonBasisNotUsable                   = "basis_not_usable"
	ReasonFactKeyNotCanonical              = "fact_key_not_canonical"
	ReasonMissingFact                      = "missing_fact"
	ReasonUnexpectedFactValue              = "unexpected_fact_value"
	ReasonEvidenceNotObserved              = "evidence_not_observed"
	ReasonAgentEditNotObserved             = "agent_edit_not_observed"
	ReasonConfidenceBelowNotAffectedBar    = "confidence_below_not_affected_bar"
	ReasonWhenPackageNotApplicable         = "when_package_not_applicable"
	ReasonWhenPackageUnresolved            = "when_package_unresolved"
	ReasonAttestationMissingExpiry         = "attestation_missing_expiry"
	ReasonFactValueNotCanonical            = "fact_value_not_canonical"
	ReasonFactValueNotBoolean              = "fact_value_not_boolean"
	ReasonFactValueOutOfDomain             = "fact_value_out_of_domain"
	ReasonMalformedPURL                    = "malformed_purl"
	ReasonVersionPURLMismatch              = "version_purl_mismatch"
	ReasonDistroAdvisoryRequired           = "distro_advisory_required"
	ReasonUnsupportedVersion               = "unsupported_version"
	ReasonAdvisoryWithoutPackage           = "advisory_without_package"
	ReasonInventoryIncomplete              = "inventory_incomplete"
	ReasonInventoryNotObserved             = "inventory_not_observed"
	ReasonComponentAbsentButInUse          = "component_absent_but_in_use"
	ReasonAdvisoryPURLRequired             = "advisory_purl_required"
	ReasonConflictingAdvisory              = "conflicting_advisory"
	ReasonAdvisoryPURLVariant              = "advisory_purl_variant"
	ReasonAdvisoryNotObserved              = "advisory_not_observed"
	ReasonUnexpectedAdvisoryValue          = "unexpected_advisory_value"
	ReasonPackNotReviewed                  = "pack_not_reviewed"
	ReasonReviewerQuorumNotMet             = "reviewer_quorum_not_met"
	ReasonPackDeprecated                   = "pack_deprecated"
	ReasonConfidenceCeilingBlocks          = "confidence_ceiling_blocks_not_affected"
	ReasonMixedJustification               = "mixed_justification"
	ReasonInsufficientProof                = "insufficient_proof"
	ReasonTreeUnknown                      = "tree_unknown"
	ReasonTreeFalseWithoutSufficient       = "tree_false_without_sufficient_proof"
	ReasonExposureUnknownTreatedExposed    = "exposure_unknown_treated_as_exposed"
	ReasonZonePolicyMissing                = "zone_policy_missing"
	ReasonExposurePortUnobserved           = "exposure_port_unobserved"
	ReasonExposurePortNotCanonical         = "exposure_port_not_canonical"
	ReasonExposurePortEvidenceInsufficient = "exposure_port_evidence_insufficient"
	ReasonEvaluationError                  = "evaluation_error"
)

// Reason kinds.
const (
	KindLeaf     = "leaf"
	KindDecision = "decision"
	KindExposure = "exposure"
	KindError    = "error"
)

// Actors: who can resolve a reason.
const (
	ActorHuman     = "human"
	ActorCollector = "collector"
	ActorReviewer  = "reviewer"
	ActorAgent     = "agent"
	ActorNone      = "none"
)

// ReasonInfo is one catalog entry. It is the machine contract that
// `verdict explain` prints.
//
// Hint is the text the report carries for the reason. For a leaf reason it is
// a template: {check} is the check id, {detail} the detail string, and
// {detail_q} the detail as a Go-quoted string. A pack's resolution_hint is
// appended after rendering. DecisionHint is set only for a code that the engine
// also emits as a decision reason with different text.
type ReasonInfo struct {
	Kind         string `json:"kind"`
	Hint         string `json:"hint"`
	DecisionHint string `json:"decision_hint,omitempty"`
	NextAction   string `json:"next_action"`
	Actor        string `json:"actor"`
}

// Reasons is the catalog of every reason code the engine emits.
var Reasons = map[string]ReasonInfo{
	ReasonMissingFact: {
		Kind:       KindLeaf,
		Hint:       "Check {check} needs fact {detail_q} in the snapshot with basis observed or attested, a confidence, and observed_at within the pack evidence_max_age of evaluation_time. v0.1 does not collect this fact and does not fill in a vendor default when the key is absent.",
		NextAction: "Collect the named fact on the asset (observed, with a confidence and observed_at) and re-run drill. Do not write the fact from assumption.",
		Actor:      ActorCollector,
	},
	ReasonStaleEvidence: {
		Kind:       KindLeaf,
		Hint:       "Evidence for check {check} is older than evidence_max_age at the explicit evaluation time. Re-collect it. Stale evidence is unknown, not a proof of not_affected.",
		NextAction: "Re-collect the evidence on the asset and re-run drill with a snapshot whose observed_at is within evidence_max_age.",
		Actor:      ActorCollector,
	},
	ReasonExpiredEvidence: {
		Kind:       KindLeaf,
		Hint:       "Evidence for check {check} expires at or before the evaluation time. Replace it. Expired evidence is unknown.",
		NextAction: "Replace the expired evidence with a fresh observation or a new attestation with a later expires_at.",
		Actor:      ActorCollector,
	},
	ReasonEvidenceTimeAfterEvaluation: {
		Kind:       KindLeaf,
		Hint:       "Evidence for check {check} is timestamped after the evaluation time, so this run cannot use it.",
		NextAction: "Check the snapshot evaluation_time and the evidence observed_at. Re-run with an evaluation time at or after the observation.",
		Actor:      ActorHuman,
	},
	ReasonInferredEvidenceDiscarded: {
		Kind:       KindLeaf,
		Hint:       "Check {check} has basis inferred. Inferred values are discarded and cannot falsify a precondition.",
		NextAction: "Replace the inferred value with an observed collection of the same fact.",
		Actor:      ActorCollector,
	},
	ReasonEvidenceNotObserved: {
		Kind:       KindLeaf,
		Hint:       "Check {check} is not basis observed. Attestations can support an affected result and cannot support not_affected.",
		NextAction: "Collect the fact as an observation on the asset if not_affected is the goal. An attestation will not clear the CVE.",
		Actor:      ActorCollector,
	},
	ReasonAgentEditNotObserved: {
		Kind:       KindLeaf,
		Hint:       "Check {check} rests on a fact whose latest edit record has actor_kind agent. An agent did not observe the asset, so the fact is read as attested whatever its basis says. It can support an affected result and cannot support not_affected.",
		NextAction: "A collector or a human observes the fact on the asset and records it with actor_kind human and an evidence file, then re-run drill. An agent cannot resolve this.",
		Actor:      ActorHuman,
	},
	ReasonConfidenceBelowNotAffectedBar: {
		Kind:         KindLeaf,
		Hint:         "Check {check} is below high confidence. Raising the number in JSON does not authenticate it, and a low value cannot support not_affected.",
		DecisionHint: "After the pack ceiling, the falsifying proof is below high confidence. not_affected was withheld.",
		NextAction:   "Re-collect the evidence with a method that yields high confidence. Do not edit the confidence field by hand.",
		Actor:        ActorCollector,
	},
	ReasonInventoryIncomplete: {
		Kind:       KindLeaf,
		Hint:       "Inventory for check {check} is not marked complete, so a missing package is not component_not_present.",
		NextAction: "Collect a complete package inventory for the asset (import with --complete only when every package source was read).",
		Actor:      ActorCollector,
	},
	ReasonInventoryNotObserved: {
		Kind:       KindLeaf,
		Hint:       "Inventory for check {check} is not a fresh observed list, so package absence or version order cannot be used.",
		NextAction: "Re-collect the package inventory as a fresh observation on the asset.",
		Actor:      ActorCollector,
	},
	ReasonDistroAdvisoryRequired: {
		Kind:       KindLeaf,
		Hint:       "Check {check} cannot treat {detail} as not-vulnerable by sorting versions. A deb, rpm, or apk build, the same component name under a different package type, a case, white-space, or separator variant of the name, or a free-form alias such as openssh-portable, needs a fresh observed advisory fact for that exact package URL. The value is affected, fixed, or not_affected. not_affected means the package was never vulnerable. fixed means a vendor fix was applied. An advisory without a purl does not cover every package.",
		NextAction: "A human reads the vendor advisory for that exact package URL and records affected, fixed, or not_affected with verdict import advisories.",
		Actor:      ActorHuman,
	},
	ReasonAdvisoryPURLRequired: {
		Kind:       KindLeaf,
		Hint:       "Advisory fact {detail_q} has no purl, so it was not applied. Set purl to the inventory package URL the advisory covers. One fact does not clear every package on the asset.",
		NextAction: "Rewrite the advisory row with the exact inventory package URL it covers.",
		Actor:      ActorHuman,
	},
	ReasonUnsupportedVersion: {
		Kind:       KindLeaf,
		Hint:       "Check {check} could not parse a version with the pack scheme. Unparsed versions are unknown, not outside the vulnerable range.",
		NextAction: "Check the package version in the inventory and the pack version_scheme. A pack fix needs review; a vendor advisory fact can resolve a distro build.",
		Actor:      ActorReviewer,
	},
	ReasonUnexpectedAdvisoryValue: {
		Kind:       KindLeaf,
		Hint:       "Advisory fact {detail_q} must be exactly affected, fixed, or not_affected. not_affected means never vulnerable, which is not the same claim as fixed.",
		NextAction: "Correct the advisory value to exactly affected, fixed, or not_affected as the vendor advisory states.",
		Actor:      ActorHuman,
	},
	ReasonZonePolicyMissing: {
		Kind:       KindExposure,
		Hint:       "No site zone policy was supplied. Packs do not name trusted or untrusted zones. Without a policy, exposure is unknown and an affected asset is exploitable with exposure_uncertainty. Pass the site policy file that lists your zone names.",
		NextAction: "Re-run drill with --policy naming the site zone policy. A human owns which zones are trusted; do not invent one.",
		Actor:      ActorHuman,
	},
	ReasonAdvisoryWithoutPackage: {
		Kind:       KindLeaf,
		Hint:       "Advisory fact {detail_q} is present but no matching package is in the inventory, so the advisory was not applied. An advisory for this CVE that names a package missing from a complete inventory also blocks component_not_present.",
		NextAction: "Reconcile the advisory file with the inventory: fix the package URL or re-collect the inventory.",
		Actor:      ActorHuman,
	},
	ReasonConflictingAdvisory: {
		Kind:       KindLeaf,
		Hint:       "Check {check} found advisory facts for {detail}, spelled the same or differently, that disagree. The engine does not pick one by order. Reconcile the sources and keep one value.",
		NextAction: "A human reconciles the advisory sources and keeps one value for the package URL.",
		Actor:      ActorHuman,
	},
	ReasonAdvisoryPURLVariant: {
		Kind:       KindLeaf,
		Hint:       "Check {check} found an advisory whose package URL differs from {detail} only by case, white space, or separators. It was not applied. Write the advisory on the exact inventory package URL.",
		NextAction: "Rewrite the advisory row on the exact inventory package URL.",
		Actor:      ActorHuman,
	},
	ReasonAdvisoryNotObserved: {
		Kind:       KindLeaf,
		Hint:       "Advisory fact {detail_q} is not fresh observed evidence, and the engine did not fall through to version sorting.",
		NextAction: "Re-record the advisory from the vendor source as a fresh observed fact.",
		Actor:      ActorCollector,
	},
	ReasonAttestationMissingExpiry: {
		Kind:       KindLeaf,
		Hint:       "Check {check} is a manual attestation and needs expires_at. An attestation without an expiry is unknown.",
		NextAction: "The attesting human re-records the attestation with an expires_at.",
		Actor:      ActorHuman,
	},
	ReasonMalformedPURL: {
		Kind:       KindLeaf,
		Hint:       "Check {check} found a package URL it could not parse. That coordinate is unknown.",
		NextAction: "Fix the collector or SBOM that produced the package URL and re-import.",
		Actor:      ActorCollector,
	},
	ReasonVersionPURLMismatch: {
		Kind:       KindLeaf,
		Hint:       "Check {check} found a package whose version field disagrees with the version in the package URL.",
		NextAction: "Fix the collector or SBOM so the version field and the package URL agree, then re-import.",
		Actor:      ActorCollector,
	},
	ReasonUnexpectedFactValue: {
		Kind:       KindLeaf,
		Hint:       "Check {check} expected fact {detail_q} to be true or false.",
		NextAction: "Re-collect the fact so its value is exactly true or false.",
		Actor:      ActorCollector,
	},
	ReasonWhenPackageUnresolved: {
		Kind:       KindLeaf,
		Hint:       "Check {check} is gated on a package version and that version could not be resolved. The mitigation was not treated as present or as proof of not_affected.",
		NextAction: "Collect a fresh observed, complete inventory that includes the gating package.",
		Actor:      ActorCollector,
	},
	ReasonWhenPackageNotApplicable: {
		Kind:       KindLeaf,
		Hint:       "Check {check} does not apply at the observed package version, so the predicate is false. When this check sits under not, the mitigation is not in effect. That is not proof of not_affected.",
		NextAction: "None for this check. Read the verdict state and the other reasons.",
		Actor:      ActorNone,
	},
	ReasonUnreadableTime: {
		Kind:       KindLeaf,
		Hint:       "Check {check} has evidence whose observed_at or expires_at is not an RFC3339 time, so its age is unknown. Unreadable evidence is unknown, not a proof of not_affected.",
		NextAction: "Fix the collector so observed_at and expires_at are RFC3339, then re-collect.",
		Actor:      ActorCollector,
	},
	ReasonUnreadableConfidence: {
		Kind:       KindLeaf,
		Hint:       "Check {check} has evidence whose confidence is not low, medium, high, or confirmed. The evidence was not used.",
		NextAction: "Re-collect the evidence with a confidence of low, medium, high, or confirmed set by the collector.",
		Actor:      ActorCollector,
	},
	ReasonBasisNotUsable: {
		Kind:       KindLeaf,
		Hint:       "Check {check} has evidence whose basis is not observed, attested, or inferred. The evidence was not used.",
		NextAction: "Re-collect the evidence with basis observed, or record a human attestation with basis attested.",
		Actor:      ActorCollector,
	},
	ReasonFactKeyNotCanonical: {
		Kind:       KindLeaf,
		Hint:       "Check {check} needs fact {detail_q}. The snapshot has a fact whose key differs only by case or surrounding white space. It was not used, and the check is unknown rather than missing or false.",
		NextAction: "Fix the collector to write the exact key, then re-collect.",
		Actor:      ActorCollector,
	},
	ReasonFactValueNotCanonical: {
		Kind:       KindLeaf,
		Hint:       "Check {check} found fact {detail_q} with a value that differs from the expected value only by case or white space. It was not repaired, so the check is unknown.",
		NextAction: "Fix the collector to write the canonical value, then re-collect.",
		Actor:      ActorCollector,
	},
	ReasonFactValueNotBoolean: {
		Kind:       KindLeaf,
		Hint:       "Check {check} expects fact {detail_q} to be exactly true or false. Any other value is unknown.",
		NextAction: "Re-collect the fact so its value is exactly true or false.",
		Actor:      ActorCollector,
	},
	ReasonFactValueOutOfDomain: {
		Kind:       KindLeaf,
		Hint:       "Check {check} found fact {detail_q} with a value outside the closed set of values for that key, so the check is unknown rather than a mismatch.",
		NextAction: "Re-collect the fact with a value from the key's documented set.",
		Actor:      ActorCollector,
	},
	ReasonComponentAbsentButInUse: {
		Kind:       KindLeaf,
		Hint:       "Check {check} found no matching package, but fact {detail_q} has a value other than exactly false, so the component may run here. Package absence was not used as component_not_present.",
		NextAction: "Reconcile the package inventory with the runtime fact: re-collect both, or find where the component is loaded from.",
		Actor:      ActorHuman,
	},
	ReasonPackNotReviewed: {
		Kind:       KindDecision,
		Hint:       "Pack status is not reviewed. Draft packs cannot produce not_affected, even when a sufficient proof of a falsified precondition exists. Reviewers are not invented to clear this.",
		NextAction: "Two named human reviewers review the pack (docs/governance.md). An agent never sets status reviewed or adds reviewer names.",
		Actor:      ActorReviewer,
	},
	ReasonReviewerQuorumNotMet: {
		Kind:       KindDecision,
		Hint:       "not_affected requires two distinct reviewer names on a reviewed pack. This pack does not meet that bar.",
		NextAction: "A second distinct human reviewer reviews the pack. Reviewer names are never fabricated.",
		Actor:      ActorReviewer,
	},
	ReasonPackDeprecated: {
		Kind:       KindDecision,
		Hint:       "The pack is deprecated. not_affected was withheld.",
		NextAction: "Use the pack that replaces it, or ask a reviewer why it was deprecated.",
		Actor:      ActorReviewer,
	},
	ReasonConfidenceCeilingBlocks: {
		Kind:       KindDecision,
		Hint:       "The pack confidence ceiling is below high, so not_affected is impossible.",
		NextAction: "Nothing on the asset changes this. Raising the ceiling is a pack change that needs review.",
		Actor:      ActorReviewer,
	},
	ReasonMixedJustification: {
		Kind:       KindDecision,
		Hint:       "The sufficient proof uses more than one OpenVEX justification. not_affected was withheld instead of publishing a single label the proof does not uniformly support.",
		NextAction: "A reviewer decides whether the pack should carry one justification for this proof.",
		Actor:      ActorReviewer,
	},
	ReasonInsufficientProof: {
		Kind:       KindDecision,
		Hint:       "There is no sufficient observed high-confidence proof that a required precondition is false.",
		NextAction: "Resolve the leaf reasons in hints (check_id set): collect the listed facts as fresh high-confidence observations.",
		Actor:      ActorCollector,
	},
	ReasonTreeUnknown: {
		Kind:       KindDecision,
		Hint:       "The condition tree is unknown. Unknown, including a single unknown branch of a disjunction, does not become not_affected.",
		NextAction: "Resolve every unknown leaf listed in hints, then re-run drill.",
		Actor:      ActorCollector,
	},
	ReasonTreeFalseWithoutSufficient: {
		Kind:       KindDecision,
		Hint:       "The condition tree is false, but the falsifying evidence is not a complete observed high-confidence proof.",
		NextAction: "Re-collect the falsifying facts as fresh observed high-confidence evidence.",
		Actor:      ActorCollector,
	},
	ReasonExposureUnknownTreatedExposed: {
		Kind:       KindExposure,
		Hint:       "Exposure for this affected asset is not a fresh high-confidence observation whose zones are all listed in trusted_zones. A missing, stale, inferred, or low-confidence record, or a zone in neither trusted_zones nor untrusted_zones, is exploitable with exposure_uncertainty. Matching is case-insensitive. Asset zone labels are not exposure evidence. A path that is only in trusted_zones stays affected as vulnerable_not_exposed.",
		NextAction: "Treat the asset as exploitable and patch. To refine, record observed reachability for the service port and pass a zone policy that lists every zone.",
		Actor:      ActorCollector,
	},
	ReasonExposurePortUnobserved: {
		Kind:       KindExposure,
		Hint:       "The pack takes the service port from a host fact (exposure.port_fact, for example config.sshd.Port) and the asset has none. A fixed default such as 22 is not assumed, so exposure is unknown and the affected asset is exploitable with exposure_uncertainty. Record every port the service listens on, from sshd -T port lines and ListenAddress ports, as an observed high-confidence fact.",
		NextAction: "Collect the listening ports with the host collector and re-import.",
		Actor:      ActorCollector,
	},
	ReasonExposurePortNotCanonical: {
		Kind:       KindExposure,
		Hint:       "The exposure port fact is not one canonical value: it must be decimal ports 1-65535 without leading zeros or white space, joined by single commas in strictly ascending order (22 or 22,2222), on the exact key with no purl and no second spelling of the key. It was not repaired or read as 22, so exposure is unknown and the asset is exploitable with exposure_uncertainty.",
		NextAction: "Fix the collector to write one canonical port list on the exact key, then re-collect.",
		Actor:      ActorCollector,
	},
	ReasonExposurePortEvidenceInsufficient: {
		Kind:       KindExposure,
		Hint:       "The exposure port fact does not meet the bar for exposure evidence: basis observed, confidence high or better, observed within evidence_max_age, and not expired at evaluation time. Exposure is unknown and the asset is exploitable with exposure_uncertainty. Re-collect the listening ports.",
		NextAction: "Re-collect the listening ports as a fresh observed high-confidence fact.",
		Actor:      ActorCollector,
	},
	ReasonEvaluationError: {
		Kind:       KindError,
		Hint:       "The condition tree could not be evaluated for this asset. The report hint carries the error text. The asset is needs_review.",
		NextAction: "Report the error text to the pack maintainers. Run verdict pack lint on the pack.",
		Actor:      ActorHuman,
	},
}

// ValidKinds and ValidActors are the closed sets for ReasonInfo.
var (
	ValidKinds  = []string{KindLeaf, KindDecision, KindExposure, KindError}
	ValidActors = []string{ActorHuman, ActorCollector, ActorReviewer, ActorAgent, ActorNone}
)

// ReasonCodes returns the catalog keys in sorted order.
func ReasonCodes() []string {
	out := make([]string, 0, len(Reasons))
	for k := range Reasons {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// renderHint fills a leaf hint template. strings.Replacer scans the template
// once, so a check id or detail that contains a placeholder is not expanded.
func renderHint(tmpl, checkID, detail string) string {
	return strings.NewReplacer(
		"{check}", checkID,
		"{detail_q}", strconv.Quote(detail),
		"{detail}", detail,
	).Replace(tmpl)
}
