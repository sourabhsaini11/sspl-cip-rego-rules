package cip.pde.bridge_branch_banking.v1_test

import data.cip.pde.bridge_branch_banking.v1 as bb

# Journey 4: a teller withdrawal of 85,000 against a dummy branch delegation of 50,000.
base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-BRANCH-BANKING", "operation": "CASH_WITHDRAWAL", "now": "2026-10-15T11:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {"amount_inr": 85000, "teller_role_valid": true, "teller_id": "TLR-1", "intent_digest": "sha256:intent-1"},
	"values": {"branch_delegation_limit_inr": 50000},
	"posture": {"operating": "NORMAL", "valid": true},
	"live": {"daily_drawn_inr": 0, "found": false},
	"customer": "cust-abc",
	"contract": "v1",
}

approved(f) := object.union(base, {"facts": object.union({"supervisor_id": "SUP-9", "approval_intent_digest": "sha256:intent-1", "supervisor_session_fresh": true}, f)})

test_above_the_delegation_refers_for_dual_control if {
	d := bb.decision with input as base
	d.result == "REFER"
	d.reason == "BRANCH_LIMIT_01"
	d.obligation_refs == ["REQUIRE_DUAL_CONTROL"]
}

test_within_the_delegation_is_permitted if {
	d := bb.decision with input as object.union(base, {"facts": {"amount_inr": 40000}})
	d.result == "PERMIT"
	d.reason == "WITHIN_DELEGATION"
}

test_an_independent_fresh_matching_approval_permits if {
	d := bb.decision with input as approved({})
	d.result == "PERMIT"
	d.reason == "DUAL_CONTROL_SATISFIED"
}

test_the_teller_cannot_approve_their_own_withdrawal if {
	d := bb.decision with input as approved({"supervisor_id": "TLR-1"})
	d.result == "DENY"
	d.reason == "SEGREGATION_OF_DUTIES"
}

test_a_replayed_approval_is_denied if {
	d := bb.decision with input as approved({"approval_intent_digest": "sha256:another-withdrawal"})
	d.result == "DENY"
	d.reason == "SEGREGATION_OF_DUTIES"
}

test_a_stale_supervisor_session_does_not_count if {
	d := bb.decision with input as approved({"supervisor_session_fresh": false})
	d.result == "REFER"
}

test_a_missing_freshness_fact_does_not_count if {
	i := object.union(base, {"facts": {"supervisor_id": "SUP-9", "approval_intent_digest": "sha256:intent-1"}})
	d := bb.decision with input as i
	d.result == "REFER"
}

test_a_user_without_the_teller_role_is_denied if {
	d := bb.decision with input as object.union(base, {"facts": {"teller_role_valid": false}})
	d.result == "DENY"
	d.reason == "ROLE_NOT_AUTHORISED"
}

test_an_amount_below_one_is_denied if {
	d := bb.decision with input as object.union(base, {"facts": {"amount_inr": 0}})
	d.reason == "INVALID_AMOUNT"
}

test_a_missing_or_mistyped_delegation_is_undefined if {
	not bb.decision with input as object.union(base, {"values": {"branch_delegation_limit_inr": "50000"}})
	not bb.decision with input as json.remove(base, ["values/branch_delegation_limit_inr"])
}

test_another_operation_is_undefined if {
	not bb.decision with input as object.union(base, {"ctx": {"operation": "CASH_DEPOSIT"}})
}
