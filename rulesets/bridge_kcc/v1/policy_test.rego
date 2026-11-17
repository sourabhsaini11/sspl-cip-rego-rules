package cip.pde.bridge_kcc.v1_test

import data.cip.pde.bridge_kcc.v1 as kcc

# Journey 5: CASE-KCC-771; the land document shows 2.4 acres, the cultivation record 2.1. A dummy
# tolerance of 100 thousandths of an acre.
base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-KCC", "operation": "KCC_ASSESS", "now": "2026-10-15T11:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {
		"land_document_area_milli_acres": 2400,
		"cultivation_area_milli_acres": 2100,
		"land_document_digest": "sha256:land",
		"cultivation_record_digest": "sha256:cultivation",
		"source_ref": "EVD-KCC-771",
	},
	"values": {"kcc_area_tolerance_milli_acres": 100},
	"posture": {"operating": "NORMAL", "valid": true},
	"live": {"daily_drawn_inr": 0, "found": false},
	"customer": "cust-abc",
	"contract": "v1",
}

test_conflicting_evidence_is_a_referral_not_a_decision if {
	d := kcc.decision with input as base
	d.result == "REFER"
	d.reason == "LAND_EVIDENCE_MISMATCH"
	d.obligation_refs == ["CERTIFIED_SOURCE_REQUIRED"]
	d.details.difference_milli_acres == 300
}

test_consistent_evidence_meets_the_prerequisite if {
	d := kcc.decision with input as object.union(base, {"facts": {"cultivation_area_milli_acres": 2350}})
	d.result == "PERMIT"
	d.reason == "EVIDENCE_CONSISTENT"
}

test_the_tolerance_is_inclusive if {
	kcc.decision.result == "PERMIT" with input as object.union(base, {"facts": {"cultivation_area_milli_acres": 2300}})
	kcc.decision.result == "REFER" with input as object.union(base, {"facts": {"cultivation_area_milli_acres": 2299}})
}

test_the_difference_is_judged_either_way_round if {
	d := kcc.decision with input as object.union(base, {"facts": {"land_document_area_milli_acres": 2100, "cultivation_area_milli_acres": 2400}})
	d.result == "REFER"
}

test_evidence_without_a_source_needs_evidence if {
	d := kcc.decision with input as json.remove(base, ["facts/source_ref"])
	d.result == "NEED_EVIDENCE"
	d.reason == "SOURCE_REF_REQUIRED"
}

test_a_missing_or_mistyped_tolerance_is_undefined if {
	not kcc.decision with input as object.union(base, {"values": {"kcc_area_tolerance_milli_acres": "100"}})
	not kcc.decision with input as json.remove(base, ["values/kcc_area_tolerance_milli_acres"])
}

test_another_operation_is_undefined if {
	not kcc.decision with input as object.union(base, {"ctx": {"operation": "KCC_SANCTION"}})
}
