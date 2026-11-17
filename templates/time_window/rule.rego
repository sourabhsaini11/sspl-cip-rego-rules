# TIME_WINDOW template (P1): requests are denied inside a daily window.
#
# The window is read from input.values[input.rule.value_key] as {"from": "HH:MM",
# "until": "HH:MM"} and denies from `from` (inclusive) to `until` (exclusive), local time.
# A window with from > until wraps midnight (23:45 to 00:15); from == until is empty.
#
# Time is judged on the PDS clock in the PDS zone (input.ctx.now and input.ctx.tz), never
# another clock. No number appears here.
#
# Fail closed: a missing window or one that is not an object of two strings leaves
# `decision` undefined. A time that does not parse is an engine error: no decision.
package cip.pde.template.time_window

window := input.values[input.rule.value_key]

valid_window if {
	is_object(window)
	is_string(window.from)
	is_string(window.until)
}

# Compare wall-clock times on one calendar day. The local date is taken from the PDS clock
# and joined to each HH:MM; every value is then parsed the same way, so they are comparable.
# (A bare "15:04" parses to year 0, whose nanosecond value overflows: do not compare those.)
now_ns := time.parse_rfc3339_ns(input.ctx.now)

local_date := time.format([now_ns, input.ctx.tz, "2006-01-02"])

local_hm := time.format([now_ns, input.ctx.tz, "15:04"])

on_day(hm) := time.parse_ns("2006-01-02 15:04", concat(" ", [local_date, hm]))

now_hm := on_day(local_hm)

from_hm := on_day(window.from)

until_hm := on_day(window.until)

in_window if {
	from_hm < until_hm
	now_hm >= from_hm
	now_hm < until_hm
}

in_window if {
	from_hm > until_hm
	now_hm >= from_hm
}

in_window if {
	from_hm > until_hm
	now_hm < until_hm
}

decision := {"allow": true, "reason": "WINDOW_OPEN"} if {
	valid_window
	not in_window
}

decision := {
	"allow": false,
	"reason": "WINDOW_CLOSED",
	"reason_code": "CIP-POL-DENY",
	"details": {"rule_id": input.rule.rule_id},
} if {
	valid_window
	in_window
}
