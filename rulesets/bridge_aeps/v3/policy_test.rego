package cip.pde.bridge_aeps.v3_test

import data.cip.pde.bridge_aeps.v3 as aeps

# Journey 6: BC-009 at a certified terminal; a dummy 2,000 withdrawal.
base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-AEPS", "operation": "AEPS_WITHDRAWAL", "now": "2026-10-15T11:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {
		"amount_inr": 2000, "auth_factor": "BIO_FP", "terminal_type": "BC_DEVICE",
		"bc_authorised": true, "device_certified": true, "terminal_active": true, "shift_permitted": true,
	},
	"values": {"daily_ceiling_inr": 10000, "step_up_threshold_inr": 5000, "bc_daily_exposure_limit_inr": 50000},
	"posture": {"operating": "NORMAL", "valid": true},
	"live": {"daily_drawn_inr": 1000, "found": true},
	"customer": "cust-abc",
	"contract": "v1",
}

test_an_authorised_bc_within_every_limit_is_permitted if {
	d := aeps.decision with input as base
	d.result == "PERMIT"
	d.reason == "WITHIN_CEILING"
	d.obligations.step_up_required == false
}

test_every_part_of_the_bc_context_is_required if {
	every f in {"bc_authorised", "device_certified", "terminal_active", "shift_permitted"} {
		d := aeps.decision with input as object.union(base, {"facts": {f: false}})
		d.result == "DENY"
		d.reason == "BC_NOT_AUTHORISED"
	}
}

test_exposure_past_the_bc_limit_is_a_referral if {
	i := object.union(base, {"values": {"bc_daily_exposure_limit_inr": 2500}})
	d := aeps.decision with input as i
	d.result == "REFER"
	d.reason == "BC_EXPOSURE_LIMIT_EXCEEDED"
	d.obligation_refs == ["BANK_OVERRIDE_REQUIRED"]
}

test_the_customer_ceiling_still_denies if {
	d := aeps.decision with input as object.union(base, {"facts": {"amount_inr": 9500}})
	d.result == "DENY"
	d.reason == "DAILY_CEILING_EXCEEDED"
	d.reason_code == "CIP-POL-LIMIT"
}

test_a_large_withdrawal_carries_the_step_up_obligation if {
	d := aeps.decision with input as object.union(base, {"facts": {"amount_inr": 6000}})
	d.result == "PERMIT"
	d.obligations.step_up_required == true
}

test_invalid_amount if {
	d := aeps.decision with input as object.union(base, {"facts": {"amount_inr": 0}})
	d.reason == "INVALID_AMOUNT"
}

test_a_missing_or_mistyped_limit_is_undefined if {
	not aeps.decision with input as object.union(base, {"values": {"bc_daily_exposure_limit_inr": "50000"}})
	not aeps.decision with input as json.remove(base, ["values/bc_daily_exposure_limit_inr"])
}
