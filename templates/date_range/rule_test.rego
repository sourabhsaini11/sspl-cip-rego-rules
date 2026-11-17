package cip.pde.template.date_range_test

import data.cip.pde.template.date_range as tpl

base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-ACCOUNTS", "operation": "ACCOUNT_STATEMENT", "now": "2026-10-15T14:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {"from_date": "2026-01-01", "to_date": "2026-01-31"},
	"values": {"R-T-RANGE": 31},
	"rule": {"rule_id": "R-T-RANGE", "rule_type": "DATE_RANGE", "value_key": "R-T-RANGE"},
}

range(f, t) := object.union(base, {"facts": {"from_date": f, "to_date": t}})

test_range_inside_the_limit_allows if {
	d := tpl.decision with input as base
	d.allow
	d.reason == "RANGE_WITHIN_LIMIT"
}

test_one_day_range_allows if {
	d := tpl.decision with input as range("2026-01-01", "2026-01-01")
	d.allow
}

test_range_one_day_over_rejects if {
	d := tpl.decision with input as range("2026-01-01", "2026-02-02")
	not d.allow
	d.reason == "RANGE_OVER_LIMIT"
	d.reason_code == "CIP-POL-LIMIT"
	d.details.rule_id == "R-T-RANGE"
}

test_reversed_range_is_undefined if {
	not tpl.decision with input as range("2026-02-01", "2026-01-01")
}

test_missing_limit_is_undefined if {
	not tpl.decision with input as object.remove(base, ["values"])
}

test_string_limit_is_undefined if {
	not tpl.decision with input as object.union(base, {"values": {"R-T-RANGE": "31"}})
}

test_negative_limit_is_undefined if {
	not tpl.decision with input as object.union(base, {"values": {"R-T-RANGE": -1}})
}
