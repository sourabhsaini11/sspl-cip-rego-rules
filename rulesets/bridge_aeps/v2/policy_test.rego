package cip.pde.bridge_aeps.v2_test

import data.cip.pde.bridge_aeps.v2 as aeps

# LLD 02-C AEPS example: ceiling 10,000, step-up above 5,000, 8,500 already drawn.
base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-AEPS", "operation": "AEPS_WITHDRAWAL", "now": "2026-10-15T14:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {"amount_inr": 12000, "auth_factor": "BIO_FP", "terminal_type": "MICRO_ATM"},
	"values": {"daily_ceiling_inr": 10000, "step_up_threshold_inr": 5000},
	"posture": {"operating": "NORMAL", "valid": true},
	"live": {"daily_drawn_inr": 8500, "found": true},
	"customer": "cust-abc",
	"contract": "v1",
}

amount(n) := object.union(base, {"facts": {"amount_inr": n}})

drawn(n) := object.union(base, {"live": {"daily_drawn_inr": n}})

test_reject_over_ceiling_with_details_and_obligation if {
	d := aeps.decision with input as base
	not d.allow
	d.reason == "DAILY_CEILING_EXCEEDED"
	d.reason_code == "CIP-POL-LIMIT"
	d.details.remaining_daily_allowance_inr == 1500
	d.obligations.step_up_required
}

test_allow_within_ceiling if {
	d := aeps.decision with input as amount(1000)
	d.allow
	d.reason == "WITHIN_CEILING"
	d.details.remaining_daily_allowance_inr == 500
	not d.obligations.step_up_required
}

test_allow_with_step_up_obligation if {
	d := aeps.decision with input as object.union(amount(6000), {"live": {"daily_drawn_inr": 0}})
	d.allow
	d.obligations.step_up_required
}

test_step_up_threshold_is_exclusive if {
	d := aeps.decision with input as object.union(amount(5000), {"live": {"daily_drawn_inr": 0}})
	d.allow
	not d.obligations.step_up_required
}

test_amount_equal_to_remaining_is_allowed if {
	aeps.decision.allow with input as amount(1500)
}

test_over_ceiling_customer_has_zero_remaining_never_negative if {
	d := aeps.decision with input as object.union(amount(100), {"live": {"daily_drawn_inr": 12000}})
	not d.allow
	d.details.remaining_daily_allowance_inr == 0
}

test_zero_and_negative_amounts_rejected if {
	zero := aeps.decision with input as amount(0)
	zero.reason == "INVALID_AMOUNT"
	zero.reason_code == "CIP-POL-DENY"
	neg := aeps.decision with input as amount(-100)
	neg.reason == "INVALID_AMOUNT"
}

test_missing_counter_is_reported_not_hidden if {
	d := aeps.decision with input as object.union(amount(1000), {"live": {"daily_drawn_inr": 0, "found": false}})
	d.allow
	d.details.live_counter_found == false
}

test_missing_ceiling_does_not_allow if {
	values := object.remove(base.values, ["daily_ceiling_inr"])
	no_ceiling := object.union(object.remove(amount(1000), ["values"]), {"values": values})
	not aeps.decision with input as no_ceiling
}

test_missing_facts_do_not_allow if {
	not aeps.decision with input as object.remove(base, ["facts"])
}

# A ceiling or threshold that is not a whole number is a malformed state document. A string
# threshold would otherwise silently switch the step-up obligation off.
test_string_ceiling_does_not_allow if {
	not aeps.decision with input as object.union(base, {"values": {"daily_ceiling_inr": "10000"}})
}

test_string_step_up_threshold_does_not_decide if {
	not aeps.decision with input as object.union(amount(500000), {"values": {"step_up_threshold_inr": "10000"}})
}

test_fractional_ceiling_does_not_allow if {
	not aeps.decision with input as object.union(base, {"values": {"daily_ceiling_inr": 10000.5}})
}
