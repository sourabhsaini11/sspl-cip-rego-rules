package cip.pde.bridge_upi.v5_test

import data.cip.pde.bridge_upi.v5 as upi

# LLD 02-C worked example: bank KGB001, 14:30 IST, 20,000 already drawn.
base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-UPI", "operation": "UPI_PAY", "now": "2026-10-15T14:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {"amount_inr": 7500, "payee_vpa": "shop@bank"},
	"values": {"per_txn_limit_inr": 10000, "daily_limit_inr": 50000, "night_cap_inr": 1000},
	"posture": {"operating": "NORMAL", "valid": true},
	"live": {"daily_drawn_inr": 20000, "found": true},
	"customer": "cust-abc",
	"contract": "v1",
}

at(now) := object.union(base, {"ctx": {"now": now}})

amount(n) := object.union(base, {"facts": {"amount_inr": n}})

test_day_allow if {
	d := upi.decision with input as base
	d.allow
	d.reason == "WITHIN_LIMITS"
	d.details.live_counter_found
}

test_night_reject if {
	d := upi.decision with input as at("2026-10-15T23:30:00+05:30")
	not d.allow
	d.reason == "NIGHT_CAP_EXCEEDED"
	d.reason_code == "CIP-POL-LIMIT"
}

test_night_small_amount_allowed if {
	d := upi.decision with input as object.union(at("2026-10-15T23:30:00+05:30"), {"facts": {"amount_inr": 500}})
	d.allow
}

test_night_judged_in_pde_zone_not_utc if {
	# 23:30 IST is 18:00 UTC: night locally, daytime in UTC.
	d := upi.decision with input as at("2026-10-15T18:00:00+00:00")
	d.reason == "NIGHT_CAP_EXCEEDED"
}

test_night_window_boundaries if {
	upi.decision.reason == "WITHIN_LIMITS" with input as at("2026-10-15T21:59:00+05:30")
	upi.decision.reason == "NIGHT_CAP_EXCEEDED" with input as at("2026-10-15T22:00:00+05:30")
	upi.decision.reason == "NIGHT_CAP_EXCEEDED" with input as at("2026-10-16T05:59:00+05:30")
	upi.decision.reason == "WITHIN_LIMITS" with input as at("2026-10-16T06:00:00+05:30")
}

test_per_txn_limit if {
	d := upi.decision with input as amount(15000)
	d.reason == "PER_TXN_LIMIT_EXCEEDED"
	d.reason_code == "CIP-POL-LIMIT"
}

test_limits_are_inclusive if {
	upi.decision.allow with input as amount(10000)
}

test_daily_limit_uses_live_counter if {
	d := upi.decision with input as object.union(base, {"live": {"daily_drawn_inr": 46000}})
	d.reason == "DAILY_LIMIT_EXCEEDED"
}

test_daily_limit_exactly_reached_is_allowed if {
	upi.decision.allow with input as object.union(amount(5000), {"live": {"daily_drawn_inr": 45000}})
}

test_zero_and_negative_amounts_rejected if {
	zero := upi.decision with input as amount(0)
	zero.reason == "INVALID_AMOUNT"
	zero.reason_code == "CIP-POL-DENY"
	neg := upi.decision with input as amount(-100)
	neg.reason == "INVALID_AMOUNT"
}

test_missing_counter_is_reported_not_hidden if {
	d := upi.decision with input as object.union(base, {"live": {"daily_drawn_inr": 0, "found": false}})
	d.allow
	d.details.live_counter_found == false
}

# Fail closed: absence of data never produces an allow.
test_missing_limits_do_not_allow if {
	not upi.decision with input as object.remove(base, ["values"])
}

test_non_numeric_limit_never_allows if {
	# A null limit is not a number; whatever the rules conclude (today: no decision, which the
	# PDE records as a REJECT RULE_UNDEFINED), it must not be an allow.
	not upi.decision.allow with input as object.union(base, {"values": {"daily_limit_inr": null}})
}

test_missing_night_cap_at_night_does_not_allow if {
	values := object.remove(base.values, ["night_cap_inr"])
	night := object.union(object.remove(at("2026-10-15T23:30:00+05:30"), ["values"]), {"values": values})
	not upi.decision with input as night
}

test_missing_per_txn_limit_does_not_allow if {
	values := object.remove(base.values, ["per_txn_limit_inr"])
	no_limit := object.union(object.remove(base, ["values"]), {"values": values})
	not upi.decision with input as no_limit
}

test_missing_facts_do_not_allow if {
	not upi.decision with input as object.remove(base, ["facts"])
}

test_unreadable_clock_does_not_allow if {
	not upi.decision with input as object.union(base, {"ctx": {"tz": "Mars/Phobos"}})
}

# A limit that is not a whole number is a malformed state document, never a permissive one:
# in Rego a number sorts before a string, so `amount <= "100000"` is true.
test_string_limits_do_not_allow if {
	v := {"per_txn_limit_inr": "100000", "daily_limit_inr": "200000", "night_cap_inr": "5000"}
	not upi.decision with input as object.union(amount(99999999), {"values": v})
}

test_one_mistyped_limit_does_not_allow if {
	not upi.decision with input as object.union(base, {"values": {"per_txn_limit_inr": "100000"}})
	not upi.decision with input as object.union(base, {"values": {"daily_limit_inr": [50000]}})
	not upi.decision with input as object.union(base, {"values": {"night_cap_inr": {"v": 1000}}})
}

test_fractional_limit_does_not_allow if {
	not upi.decision with input as object.union(base, {"values": {"per_txn_limit_inr": 10000.5}})
}

test_an_amount_of_one_is_valid if {
	d := upi.decision with input as amount(1)
	d.allow
}

test_the_night_cap_is_inclusive if {
	d := upi.decision with input as object.union(at("2026-10-15T23:30:00+05:30"), {"facts": {"amount_inr": 1000}})
	d.allow
	d2 := upi.decision with input as object.union(at("2026-10-15T23:30:00+05:30"), {"facts": {"amount_inr": 1001}})
	not d2.allow
	d2.reason == "NIGHT_CAP_EXCEEDED"
}
