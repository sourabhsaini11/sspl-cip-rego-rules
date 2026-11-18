package cip.pde.bridge_branch_banking.v2_test

import data.cip.pde.bridge_branch_banking.v2 as bb

# Journey 4: a teller withdrawal of 85,000 against a dummy branch delegation of 50,000. The supervisor's approval is
# a completion of REQUIRE_DUAL_CONTROL that the PDS has verified (docs/rules-contract.md, section 4.4), never a fact
# the branch system sends: no flag can turn a REFER into a PERMIT (document section 8).
base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-BRANCH-BANKING", "operation": "CASH_WITHDRAWAL", "now": "2026-10-15T11:30:00+05:30", "tz": "Asia/Kolkata", "completions": []},
	"facts": {"amount_inr": 85000, "teller_role_valid": true, "teller_id": "TLR-1"},
	"values": {"branch_delegation_limit_inr": 50000},
	"posture": {"operating": "NORMAL", "valid": true},
	"live": {"daily_drawn_inr": 0, "found": false},
	"customer": "cust-abc",
	"contract": "v1",
}

done(ref, by) := {"obligation_ref": ref, "completed_by": by, "completed_at": "2026-10-15T11:29:00+05:30"}

with_completions(cs) := object.union(base, {"ctx": {"completions": cs}})

facts(f) := object.union(base, {"facts": f})

test_above_the_delegation_refers_for_dual_control if {
	d := bb.decision with input as base
	d.result == "REFER"
	d.reason == "BRANCH_LIMIT_01"
	d.reason_code == "CIP-POL-LIMIT"
	d.obligation_refs == ["REQUIRE_DUAL_CONTROL"]
}

test_an_independent_verified_completion_permits if {
	d := bb.decision with input as with_completions([done("REQUIRE_DUAL_CONTROL", "SUP-9")])
	d.result == "PERMIT"
	d.reason == "DUAL_CONTROL_SATISFIED"
}

test_the_teller_cannot_approve_their_own_withdrawal if {
	d := bb.decision with input as with_completions([done("REQUIRE_DUAL_CONTROL", "TLR-1")])
	d.result == "DENY"
	d.reason == "SEGREGATION_OF_DUTIES"
	d.reason_code == "CIP-POL-TRUST"
}

test_one_completion_by_the_teller_among_several_is_still_a_breach if {
	d := bb.decision with input as with_completions([done("REQUIRE_DUAL_CONTROL", "SUP-9"), done("REQUIRE_DUAL_CONTROL", "TLR-1")])
	d.result == "DENY"
	d.reason == "SEGREGATION_OF_DUTIES"
}

test_a_completion_of_another_obligation_does_not_count if {
	d := bb.decision with input as with_completions([done("OTP_OR_APPROVED_FACTOR", "SUP-9")])
	d.result == "REFER"
}

test_a_missing_completion_list_refers if {
	d := bb.decision with input as json.remove(base, ["ctx/completions"])
	d.result == "REFER"
}

test_a_flag_in_the_facts_cannot_stand_in_for_a_completion if {
	d := bb.decision with input as facts({"amount_inr": 85000, "teller_role_valid": true, "teller_id": "TLR-1", "supervisor_id": "SUP-9", "supervisor_session_fresh": true, "approval_intent_digest": "x"})
	d.result == "REFER"
}

test_within_the_delegation_is_permitted_without_approval if {
	d := bb.decision with input as facts({"amount_inr": 40000, "teller_role_valid": true, "teller_id": "TLR-1"})
	d.result == "PERMIT"
	d.reason == "WITHIN_DELEGATION"
}

test_the_delegation_limit_is_inclusive if {
	at := facts({"amount_inr": 50000, "teller_role_valid": true, "teller_id": "TLR-1"})
	bb.decision.result == "PERMIT" with input as at
	over := facts({"amount_inr": 50001, "teller_role_valid": true, "teller_id": "TLR-1"})
	bb.decision.result == "REFER" with input as over
}

test_a_teller_without_the_role_is_denied if {
	d := bb.decision with input as facts({"amount_inr": 40000, "teller_role_valid": false, "teller_id": "TLR-1"})
	d.result == "DENY"
	d.reason == "ROLE_NOT_AUTHORISED"
	d.reason_code == "CIP-POL-TRUST"
}

test_a_role_breach_is_a_deny_even_with_a_completion if {
	v := object.union(with_completions([done("REQUIRE_DUAL_CONTROL", "SUP-9")]), {"facts": {"teller_role_valid": false}})
	d := bb.decision with input as v
	d.reason == "ROLE_NOT_AUTHORISED"
}

test_an_amount_of_one_is_valid_and_zero_is_not if {
	one := facts({"amount_inr": 1, "teller_role_valid": true, "teller_id": "TLR-1"})
	bb.decision.result == "PERMIT" with input as one
	zero := facts({"amount_inr": 0, "teller_role_valid": true, "teller_id": "TLR-1"})
	d := bb.decision with input as zero
	d.result == "DENY"
	d.reason == "INVALID_AMOUNT"
	d.reason_code == "CIP-POL-DENY"
}

test_a_missing_delegation_limit_leaves_the_decision_undefined if {
	not bb.decision with input as json.remove(base, ["values/branch_delegation_limit_inr"])
}

test_a_malformed_delegation_limit_leaves_the_decision_undefined if {
	not bb.decision with input as object.union(base, {"values": {"branch_delegation_limit_inr": "50000"}})
}

test_another_operation_leaves_the_decision_undefined if {
	not bb.decision with input as object.union(base, {"ctx": {"operation": "CASH_DEPOSIT"}})
}

# A delegation of zero puts a one-rupee withdrawal above it: the smallest amount each dual-control rule must still decide.
zero_delegation(cs) := object.union(with_completions(cs), {"facts": {"amount_inr": 1}, "values": {"branch_delegation_limit_inr": 0}})

test_one_rupee_above_a_zero_delegation_refers if {
	d := bb.decision with input as zero_delegation([])
	d.result == "REFER"
}

test_one_rupee_above_a_zero_delegation_is_a_breach_when_the_teller_approves if {
	d := bb.decision with input as zero_delegation([done("REQUIRE_DUAL_CONTROL", "TLR-1")])
	d.reason == "SEGREGATION_OF_DUTIES"
}

test_one_rupee_above_a_zero_delegation_is_permitted_with_an_independent_approver if {
	d := bb.decision with input as zero_delegation([done("REQUIRE_DUAL_CONTROL", "SUP-9")])
	d.reason == "DUAL_CONTROL_SATISFIED"
}
