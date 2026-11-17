package cip.pde.template.time_window_test

import data.cip.pde.template.time_window as tpl

base := {
	"ctx": {"bank_id": "KGB001", "profile": "BRIDGE-PAYMENTS", "operation": "IMPS_TRANSFER", "now": "2026-10-15T12:00:00+05:30", "tz": "Asia/Kolkata"},
	"facts": {},
	"values": {"R-T-WIN": {"from": "23:45", "until": "00:15"}},
	"rule": {"rule_id": "R-T-WIN", "rule_type": "TIME_WINDOW", "value_key": "R-T-WIN"},
}

at(now) := object.union(base, {"ctx": {"now": now}})

window(from, until) := object.union(base, {"values": {"R-T-WIN": {"from": from, "until": until}}})

test_outside_the_window_allows if {
	d := tpl.decision with input as base
	d.allow
	d.reason == "WINDOW_OPEN"
}

test_inside_a_window_that_wraps_midnight_rejects_before_midnight if {
	d := tpl.decision with input as at("2026-10-15T23:50:00+05:30")
	not d.allow
	d.reason == "WINDOW_CLOSED"
	d.reason_code == "CIP-POL-DENY"
	d.details.rule_id == "R-T-WIN"
}

test_inside_a_window_that_wraps_midnight_rejects_after_midnight if {
	d := tpl.decision with input as at("2026-10-16T00:10:00+05:30")
	not d.allow
}

test_window_start_is_closed if {
	d := tpl.decision with input as at("2026-10-15T23:45:00+05:30")
	not d.allow
}

test_window_end_is_open if {
	d := tpl.decision with input as at("2026-10-16T00:15:00+05:30")
	d.allow
}

test_same_day_window_denies_inside if {
	d := tpl.decision with input as object.union(window("09:00", "21:00"), {"ctx": {"now": "2026-10-15T10:00:00+05:30"}})
	not d.allow
}

test_same_day_window_end_is_open if {
	d := tpl.decision with input as object.union(window("09:00", "21:00"), {"ctx": {"now": "2026-10-15T21:00:00+05:30"}})
	d.allow
}

test_the_window_is_judged_in_the_pde_zone_not_utc if {
	# 18:30 UTC is 00:00 IST: inside the 23:45-00:15 window only when read in Asia/Kolkata.
	d := tpl.decision with input as at("2026-10-15T18:30:00Z")
	not d.allow
}

test_an_empty_window_never_denies if {
	d := tpl.decision with input as window("09:00", "09:00")
	d.allow
}

test_missing_window_is_undefined if {
	not tpl.decision with input as object.remove(base, ["values"])
}

test_a_window_that_is_not_an_object_is_undefined if {
	not tpl.decision with input as object.union(base, {"values": {"R-T-WIN": "23:45-00:15"}})
}
