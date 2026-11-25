package cip.pde.bridge_balance_enquiry_e2e.v2_test

import data.cip.pde.bridge_balance_enquiry_e2e.v2 as bal

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

# ---- v2: the night rule (STAND-IN: the night allowance is the signed daily quota minus one, so 4 of 5) ----

at(ts) := object.union(base, {"ctx": object.union(base.ctx, {"now": ts})})

night(n) := object.union(at("2026-11-20T23:30:00+05:30"), {"live": {"found": true, "daily_drawn_inr": n}})

test_by_day_only_the_daily_quota_applies if {
	d := bal.decision with input as with_live(4)
	d.allow
}

test_at_night_under_the_night_limit_is_allowed if {
	d := bal.decision with input as night(3)
	d.allow
	d.reason == "BALANCE_WITHIN_DAILY_QUOTA"
}

test_at_night_over_the_night_limit_is_denied if {
	d := bal.decision with input as night(4)
	not d.allow
	d.reason == "NIGHT_CAP_EXCEEDED"
	d.reason_code == "CIP-POL-LIMIT"
}

test_the_night_limit_wins_over_the_daily_quota if {
	d := bal.decision with input as night(5)
	not d.allow
	d.reason == "NIGHT_CAP_EXCEEDED"
}

test_the_same_count_by_day_is_the_daily_quota_not_the_night_limit if {
	d := bal.decision with input as with_live(4)
	d.allow
	e := bal.decision with input as with_live(5)
	not e.allow
	e.reason == "BALANCE_DAILY_QUOTA_EXCEEDED"
}

test_night_starts_at_17_30_and_ends_at_06_00 if {
	d1730 := bal.decision with input as object.union(night(4), {"ctx": object.union(base.ctx, {"now": "2026-11-20T17:30:00+05:30"})})
	not d1730.allow
	d1729 := bal.decision with input as object.union(with_live(4), {"ctx": object.union(base.ctx, {"now": "2026-11-20T17:29:00+05:30"})})
	d1729.allow
	d0559 := bal.decision with input as object.union(with_live(4), {"ctx": object.union(base.ctx, {"now": "2026-11-21T05:59:00+05:30"})})
	not d0559.allow
	d0600 := bal.decision with input as object.union(with_live(4), {"ctx": object.union(base.ctx, {"now": "2026-11-21T06:00:00+05:30"})})
	d0600.allow
}

test_the_night_is_read_in_the_states_zone_not_utc if {
	# 23:30 IST is 18:00 UTC: still night in Asia/Kolkata.
	d := bal.decision with input as night(4)
	not d.allow
	# 10:00 IST is 04:30 UTC: still day in Asia/Kolkata.
	e := bal.decision with input as object.union(with_live(4), {"ctx": object.union(base.ctx, {"now": "2026-11-20T10:00:00+05:30"})})
	e.allow
}

test_the_night_allowance_follows_the_signed_quota if {
	# quota 3 -> night allowance 2: the third enquiry at night is denied by the night rule.
	three := object.union(night(2), {"values": {"R-ACC-BAL-DAILY": 3, "R-ACC-READ-DAILY": 10}})
	d := bal.decision with input as three
	not d.allow
	d.reason == "NIGHT_CAP_EXCEEDED"
}

test_a_zero_quota_at_night_is_still_a_denial if {
	zero := object.union(night(0), {"values": {"R-ACC-BAL-DAILY": 0, "R-ACC-READ-DAILY": 10}})
	d := bal.decision with input as zero
	not d.allow
}

test_the_early_evening_is_night_from_17_30_on if {
	evening := object.union(with_live(4), {"ctx": object.union(base.ctx, {"now": "2026-11-20T19:00:00+05:30"})})
	d := bal.decision with input as evening
	not d.allow
	d.reason == "NIGHT_CAP_EXCEEDED"
	afternoon := object.union(with_live(4), {"ctx": object.union(base.ctx, {"now": "2026-11-20T16:45:00+05:30"})})
	e := bal.decision with input as afternoon
	e.allow
}
