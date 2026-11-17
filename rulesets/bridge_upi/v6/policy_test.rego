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
