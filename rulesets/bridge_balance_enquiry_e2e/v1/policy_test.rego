package cip.pde.bridge_balance_enquiry_e2e.v1_test

import data.cip.pde.bridge_balance_enquiry_e2e.v1 as bal

base := {
	"ctx": {"bank_id": "JKSCB001", "profile": "BRIDGE-BALANCE-ENQUIRY-E2E", "operation": "BALANCE-ENQUIRY-E2E", "now": "2026-11-20T14:30:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {},
	"values": {"R-ACC-BAL-DAILY": 5, "R-ACC-READ-DAILY": 10},
	"posture": {"operating": "NORMAL", "valid": true},
	"live": {"found": true, "daily_drawn_inr": 2},
	"customer": "cust-abc",
	"contract": "v1",
}

with_live(n) := object.union(base, {"live": {"found": true, "daily_drawn_inr": n}})

test_allow_under_the_quota if {
	d := bal.decision with input as base
	d.allow
	d.reason == "BALANCE_WITHIN_DAILY_QUOTA"
}

test_the_last_permitted_enquiry_is_allowed if {
	d := bal.decision with input as with_live(4)
	d.allow
}

test_reject_when_the_quota_is_used_up if {
	d := bal.decision with input as with_live(5)
	not d.allow
	d.reason == "BALANCE_DAILY_QUOTA_EXCEEDED"
	d.reason_code == "CIP-POL-LIMIT"
}

test_reject_when_the_count_is_past_the_quota if {
	d := bal.decision with input as with_live(9)
	not d.allow
}

test_no_counter_yet_reads_as_zero if {
	fresh := object.union(base, {"live": {"found": false, "daily_drawn_inr": 0}})
	d := bal.decision with input as fresh
	d.allow
}

test_the_limit_is_data_not_code if {
	tight := object.union(base, {"values": {"R-ACC-BAL-DAILY": 2}})
	d := bal.decision with input as tight
	not d.allow
	wide := object.union(base, {"values": {"R-ACC-BAL-DAILY": 50}})
	e := bal.decision with input as wide
	e.allow
}

test_a_zero_limit_allows_nothing if {
	zero := object.union(base, {"values": {"R-ACC-BAL-DAILY": 0}})
	d := bal.decision with input as zero
	not d.allow
}

test_missing_limit_is_undefined_never_an_allow if {
	no_values := object.remove(base, ["values"])
	not bal.decision with input as no_values
	no_limit := object.union(no_values, {"values": {"R-ACC-READ-DAILY": 10}})
	not bal.decision with input as no_limit
}

test_a_mistyped_limit_is_undefined if {
	text := object.union(base, {"values": {"R-ACC-BAL-DAILY": "5"}})
	not bal.decision with input as text
	fractional := object.union(base, {"values": {"R-ACC-BAL-DAILY": 4.5}})
	not bal.decision with input as fractional
	negative := object.union(base, {"values": {"R-ACC-BAL-DAILY": -1}})
	not bal.decision with input as negative
}

test_a_mistyped_counter_is_undefined if {
	not bal.decision with input as with_live("2")
	not bal.decision with input as with_live(-1)
	not bal.decision with input as with_live(1.5)
}
