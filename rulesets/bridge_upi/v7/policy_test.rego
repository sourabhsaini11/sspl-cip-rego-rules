package cip.pde.bridge_upi.v7_test

import data.cip.pde.bridge_upi.v7 as upi

# The document's acceptance scenario (section 3): KGB001 has raised its UPI limit to 20,000, the L4
# posture is GUARDED with a cap of 8,000, and a customer pays 12,000. The values are the document's
# examples, not SSPL-approved limits.
base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-UPI", "operation": "UPI_PAY", "now": "2026-10-15T14:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {"amount_inr": 12000, "payee_vpa": "shop@bank", "device_verified": true},
	"values": {"per_txn_limit_inr": 20000, "daily_limit_inr": 50000, "night_cap_inr": 20000, "step_up_threshold_inr": 3000, "guarded_cap_inr": 8000},
	"posture": {"operating": "GUARDED", "valid": true},
	"live": {"daily_drawn_inr": 0, "found": true},
	"customer": "cust-abc",
	"contract": "v1",
}

amount(n) := object.union(base, {"facts": {"amount_inr": n}})

normal := object.union(base, {"posture": {"operating": "NORMAL"}})

test_guarded_posture_denies_a_payment_above_the_cap if {
	d := upi.decision with input as base
	d.result == "DENY"
	d.reason == "UPI_GUARDED_LIMIT_EXCEEDED"
	d.reason_code == "CIP-POL-LIMIT"
}

test_the_denial_states_the_limit_that_applied if {
	d := upi.decision with input as base
	d.details.effective_limit_inr == 8000
}

test_guarded_posture_permits_a_payment_at_the_cap if {
	d := upi.decision with input as amount(8000)
	d.result == "PERMIT"
}

test_guarded_posture_denies_one_rupee_above_the_cap if {
	d := upi.decision with input as amount(8001)
	d.reason == "UPI_GUARDED_LIMIT_EXCEEDED"
}

test_normal_posture_permits_the_same_payment if {
	d := upi.decision with input as normal
	d.result == "PERMIT"
	d.reason == "WITHIN_LIMITS"
}

test_a_cap_above_the_bank_limit_does_not_loosen_it if {
	# The posture may only narrow (FF-14): 30,000 guarded cap, 20,000 per-transaction limit.
	v := object.union(base, {"values": {"guarded_cap_inr": 30000}, "facts": {"amount_inr": 25000}})
	d := upi.decision with input as v
	d.result == "DENY"
	d.reason == "PER_TXN_LIMIT_EXCEEDED"
}

test_a_limit_breach_wins_over_the_guarded_cap if {
	d := upi.decision with input as amount(25000)
	d.reason == "PER_TXN_LIMIT_EXCEEDED"
}

test_guarded_posture_without_a_cap_is_undefined if {
	v := json.remove(base, ["values/guarded_cap_inr"])
	not upi.decision with input as v
}

test_guarded_posture_with_a_malformed_cap_is_undefined if {
	v := object.union(base, {"values": {"guarded_cap_inr": "8000"}})
	not upi.decision with input as v
}

test_normal_posture_does_not_need_a_cap if {
	v := json.remove(normal, ["values/guarded_cap_inr"])
	d := upi.decision with input as v
	d.result == "PERMIT"
}

test_a_guarded_payment_above_the_cap_never_steps_up if {
	v := object.union(base, {"facts": {"device_verified": false}})
	d := upi.decision with input as v
	d.result == "DENY"
}

test_unverified_device_above_threshold_within_the_cap_steps_up if {
	v := object.union(base, {"facts": {"amount_inr": 5000, "device_verified": false}})
	d := upi.decision with input as v
	d.result == "STEP_UP"
	d.reason == "UPI_DEVICE_RISK"
}

test_night_cap_still_applies_under_guarded if {
	v := object.union(amount(5000), {"ctx": {"now": "2026-10-15T23:30:00+05:30"}, "values": {"night_cap_inr": 1000}})
	d := upi.decision with input as v
	d.reason == "NIGHT_CAP_EXCEEDED"
}

test_the_daily_limit_still_applies_under_guarded if {
	v := object.union(amount(5000), {"live": {"daily_drawn_inr": 48000}})
	d := upi.decision with input as v
	d.reason == "DAILY_LIMIT_EXCEEDED"
}

# Boundaries of the rules v7 inherits from v6. Each pins one comparison: one rupee or one minute either side.
at(now) := object.union(normal, {"ctx": {"now": now}, "facts": {"amount_inr": 500}})

test_22_00_is_night_and_21_59_is_day if {
	n := object.union(at("2026-10-15T22:00:00+05:30"), {"values": {"night_cap_inr": 400}})
	d := upi.decision with input as n
	d.reason == "NIGHT_CAP_EXCEEDED"
	e := object.union(at("2026-10-15T21:59:00+05:30"), {"values": {"night_cap_inr": 400}})
	upi.decision.result == "PERMIT" with input as e
}

test_06_00_is_day_and_05_59_is_night if {
	n := object.union(at("2026-10-15T05:59:00+05:30"), {"values": {"night_cap_inr": 400}})
	d := upi.decision with input as n
	d.reason == "NIGHT_CAP_EXCEEDED"
	e := object.union(at("2026-10-15T06:00:00+05:30"), {"values": {"night_cap_inr": 400}})
	upi.decision.result == "PERMIT" with input as e
}

test_an_amount_of_one_is_valid_and_zero_is_not if {
	one := object.union(normal, {"facts": {"amount_inr": 1}})
	upi.decision.result == "PERMIT" with input as one
	zero := object.union(normal, {"facts": {"amount_inr": 0}})
	d := upi.decision with input as zero
	d.reason == "INVALID_AMOUNT"
	d.reason_code == "CIP-POL-DENY"
}

test_the_night_cap_is_inclusive if {
	t := "2026-10-15T23:30:00+05:30"
	ok := object.union(normal, {"ctx": {"now": t}, "values": {"night_cap_inr": 1000}, "facts": {"amount_inr": 1000}})
	upi.decision.result == "PERMIT" with input as ok
	over := object.union(normal, {"ctx": {"now": t}, "values": {"night_cap_inr": 1000}, "facts": {"amount_inr": 1001}})
	upi.decision.reason == "NIGHT_CAP_EXCEEDED" with input as over
}

test_the_per_transaction_limit_is_inclusive if {
	ok := object.union(normal, {"facts": {"amount_inr": 20000}})
	upi.decision.result == "PERMIT" with input as ok
	over := object.union(normal, {"facts": {"amount_inr": 20001}})
	upi.decision.reason == "PER_TXN_LIMIT_EXCEEDED" with input as over
}

test_the_daily_limit_is_inclusive if {
	ok := object.union(normal, {"facts": {"amount_inr": 1000}, "live": {"daily_drawn_inr": 49000}})
	upi.decision.result == "PERMIT" with input as ok
	over := object.union(normal, {"facts": {"amount_inr": 1001}, "live": {"daily_drawn_inr": 49000}})
	upi.decision.reason == "DAILY_LIMIT_EXCEEDED" with input as over
}

test_the_step_up_threshold_is_exclusive if {
	at_threshold := object.union(normal, {"facts": {"amount_inr": 3000, "device_verified": false}})
	upi.decision.result == "PERMIT" with input as at_threshold
	above := object.union(normal, {"facts": {"amount_inr": 3001, "device_verified": false}})
	upi.decision.result == "STEP_UP" with input as above
}

test_the_guarded_cap_is_inclusive_under_a_step_up_too if {
	at_cap := object.union(base, {"facts": {"amount_inr": 8000, "device_verified": false}})
	upi.decision.result == "STEP_UP" with input as at_cap
}
