package cip.pde.bridge_upi.v6_test

import data.cip.pde.bridge_upi.v6 as upi

# Journey 1 of the PDE architecture document: bank KGB001, 14:30 IST. The values are examples, not
# SSPL-approved limits.
base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-UPI", "operation": "UPI_PAY", "now": "2026-10-15T14:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {"amount_inr": 5000, "payee_vpa": "shop@bank", "device_verified": false},
	"values": {"per_txn_limit_inr": 10000, "daily_limit_inr": 50000, "night_cap_inr": 1000, "step_up_threshold_inr": 3000},
	"posture": {"operating": "NORMAL", "valid": true},
	"live": {"daily_drawn_inr": 0, "found": true},
	"customer": "cust-abc",
	"contract": "v1",
}

facts(f) := object.union(base, {"facts": f})

test_unverified_device_above_threshold_steps_up if {
	d := upi.decision with input as base
	d.result == "STEP_UP"
	d.reason == "UPI_DEVICE_RISK"
	d.reason_code == "CIP-POL-TRUST"
	d.obligation_refs == ["OTP_OR_APPROVED_FACTOR"]
}

test_verified_device_is_permitted if {
	d := upi.decision with input as facts({"amount_inr": 5000, "payee_vpa": "shop@bank", "device_verified": true})
	d.result == "PERMIT"
	d.reason == "WITHIN_LIMITS"
}

test_unverified_device_at_or_below_threshold_is_permitted if {
	d := upi.decision with input as facts({"amount_inr": 3000, "payee_vpa": "shop@bank", "device_verified": false})
	d.result == "PERMIT"
}

test_a_limit_breach_is_a_deny_never_a_step_up if {
	d := upi.decision with input as facts({"amount_inr": 20000, "payee_vpa": "shop@bank", "device_verified": false})
	d.result == "DENY"
	d.reason == "PER_TXN_LIMIT_EXCEEDED"
	d.reason_code == "CIP-POL-LIMIT"
}

test_night_cap_still_applies if {
	d := upi.decision with input as object.union(base, {"ctx": {"now": "2026-10-15T23:30:00+05:30"}})
	d.result == "DENY"
	d.reason == "NIGHT_CAP_EXCEEDED"
}

test_invalid_amount if {
	d := upi.decision with input as facts({"amount_inr": 0, "payee_vpa": "shop@bank", "device_verified": true})
	d.reason == "INVALID_AMOUNT"
	d.reason_code == "CIP-POL-DENY"
}

test_missing_threshold_is_undefined if {
	not upi.decision with input as json.remove(base, ["values/step_up_threshold_inr"])
}

test_a_string_threshold_is_undefined if {
	not upi.decision with input as object.union(base, {"values": {"step_up_threshold_inr": "3000"}})
}

# ---- boundaries: each comparison is pinned from both sides ----

verified(f) := object.union(base, {"facts": object.union({"device_verified": true}, f)})

test_an_amount_of_one_is_valid if {
	d := upi.decision with input as verified({"amount_inr": 1})
	d.result == "PERMIT"
}

test_the_night_window_boundaries if {
	night := {"amount_inr": 5000}
	upi.decision.result == "PERMIT" with input as object.union(verified(night), {"ctx": {"now": "2026-10-15T21:59:00+05:30"}})
	upi.decision.reason == "NIGHT_CAP_EXCEEDED" with input as object.union(verified(night), {"ctx": {"now": "2026-10-15T22:00:00+05:30"}})
	upi.decision.reason == "NIGHT_CAP_EXCEEDED" with input as object.union(verified(night), {"ctx": {"now": "2026-10-16T05:59:00+05:30"}})
	upi.decision.result == "PERMIT" with input as object.union(verified(night), {"ctx": {"now": "2026-10-16T06:00:00+05:30"}})
}

test_the_night_cap_is_inclusive if {
	late := {"ctx": {"now": "2026-10-15T23:30:00+05:30"}}
	d := upi.decision with input as object.union(verified({"amount_inr": 1000}), late)
	d.result == "PERMIT"
	d2 := upi.decision with input as object.union(verified({"amount_inr": 1001}), late)
	d2.reason == "NIGHT_CAP_EXCEEDED"
}

test_the_per_transaction_limit_is_inclusive if {
	d := upi.decision with input as verified({"amount_inr": 10000})
	d.result == "PERMIT"
	d2 := upi.decision with input as verified({"amount_inr": 10001})
	d2.reason == "PER_TXN_LIMIT_EXCEEDED"
}

drawn_of(n) := object.union(verified({"amount_inr": 10000}), {"live": {"daily_drawn_inr": n}})

test_the_daily_limit_adds_what_was_already_drawn if {
	upi.decision.result == "PERMIT" with input as drawn_of(40000)
	upi.decision.reason == "DAILY_LIMIT_EXCEEDED" with input as drawn_of(40001)
	upi.decision.reason == "DAILY_LIMIT_EXCEEDED" with input as drawn_of(45000)
}

test_the_step_up_threshold_is_exclusive if {
	upi.decision.result == "PERMIT" with input as object.union(base, {"facts": {"amount_inr": 3000}})
	upi.decision.result == "STEP_UP" with input as object.union(base, {"facts": {"amount_inr": 3001}})
}
