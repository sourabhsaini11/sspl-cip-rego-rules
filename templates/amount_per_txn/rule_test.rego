package cip.pde.template.amount_per_txn_test

import data.cip.pde.template.amount_per_txn as tpl

base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-UPI", "operation": "IMPS_TRANSFER", "now": "2026-10-15T14:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {"amount_inr": 7500},
	"values": {"R-T-MAX": 10000},
	"rule": {"rule_id": "R-T-MAX", "rule_type": "AMOUNT_PER_TXN", "value_key": "R-T-MAX"},
}

with_amount(n) := object.union(base, {"facts": {"amount_inr": n}})

with_limit(v) := object.union(base, {"values": {"R-T-MAX": v}})

test_within_limit_allows if {
	d := tpl.decision with input as base
	d.allow
	d.reason == "AMOUNT_WITHIN_LIMIT"
}

test_exactly_the_limit_allows if {
	d := tpl.decision with input as with_amount(10000)
	d.allow
}

test_over_limit_rejects_with_the_rule_id if {
	d := tpl.decision with input as with_amount(10001)
	not d.allow
	d.reason == "AMOUNT_OVER_LIMIT"
	d.reason_code == "CIP-POL-LIMIT"
	d.details.rule_id == "R-T-MAX"
}

test_limit_comes_from_the_bound_key if {
	d := tpl.decision with input as object.union(base, {"values": {"R-T-MAX": 10000, "OTHER": 1}, "rule": {"value_key": "OTHER"}})
	not d.allow
}

test_missing_limit_is_undefined if {
	not tpl.decision with input as object.remove(base, ["values"])
}

test_unknown_key_is_undefined if {
	not tpl.decision with input as object.union(base, {"rule": {"value_key": "NOPE"}})
}

test_string_limit_is_undefined if {
	not tpl.decision with input as with_limit("100000")
}

test_fractional_limit_is_undefined if {
	not tpl.decision with input as with_limit(10000.5)
}

test_non_numeric_amount_is_undefined if {
	not tpl.decision with input as object.union(base, {"facts": {"amount_inr": "7500"}})
}
