# BRIDGE-BALANCE-ENQUIRY-E2E ruleset v2 - the v1 daily quota plus a night rule, so the night-cap negative case can be
# exercised end to end on the dev server with the state the Resolution Engine already signs.
#
# v1 behaviour is kept: an enquiry is allowed while count + 1 does not pass the daily quota
# (input.values["R-ACC-BAL-DAILY"], the signed state's parameter; input.live.daily_drawn_inr is the count).
#
# New in v2: between 15:00 and 15:50 in the state's time zone (input.ctx.tz, Asia/Kolkata on dev) the allowance is
# one enquiry smaller than the daily quota, so with a quota of 5 the 5th enquiry at night is a DENY
# NIGHT_CAP_EXCEEDED (CIP-POL-LIMIT), ahead of the daily quota. By day only the daily quota applies.
#
# The night window is 15:00 to 15:50 (not 22:00 to 06:00) ONLY so the rule can be tested in the afternoon; the gate allows
# the numbers 15 and 50 in this one ruleset (devOnlyLiterals in the rules-check). Do not promote v2.
#
# STAND-IN, DEV TEST ONLY. The night allowance is derived from the signed quota (quota minus one) because the
# rules-check gate forbids a limit written in a rule (limits belong in input.values) and the profile has no night
# value yet: R-ACC-BAL-DAILY is the only balance value in the state. The real design is a night limit of its own,
# issued from a rule catalogue entry into the signed state, read here as input.values[<its id>]. Do not promote v2.
#
# Rules carry no data. Input contract: v1.
# Fail closed: a missing or non-whole limit, or a counter that is not a whole number, leaves `decision` undefined,
# which the PDE records as REJECT RULE_UNDEFINED.
package cip.pde.bridge_balance_enquiry_e2e.v2

# Enquiries allowed per day while it is night: the signed daily quota minus one (STAND-IN, see the header).
night_limit := input.values["R-ACC-BAL-DAILY"] - 1

night_start_hour := 15

night_end_hour := 15

night_end_minute := 50

local_clock := time.clock([time.parse_rfc3339_ns(input.ctx.now), input.ctx.tz])

local_hour := local_clock[0]

local_minute := local_clock[1]

# TEST WINDOW: 15:00 to 15:50 on the same day (the start is inclusive, the end is exclusive).
is_night if {
	local_hour == night_start_hour
	local_minute < night_end_minute
}

whole_number(x) if {
	is_number(x)
	x == round(x)
}

limit_ok if {
	whole_number(input.values["R-ACC-BAL-DAILY"])
	input.values["R-ACC-BAL-DAILY"] >= 0
	whole_number(input.live.daily_drawn_inr)
	input.live.daily_drawn_inr >= 0
}

night_exceeded if {
	is_night
	input.live.daily_drawn_inr + 1 > night_limit
}

daily_exceeded if input.live.daily_drawn_inr + 1 > input.values["R-ACC-BAL-DAILY"]

decision := {
	"allow": true,
	"reason": "BALANCE_WITHIN_DAILY_QUOTA",
	"details": {},
	"obligations": {},
} if {
	limit_ok
	not night_exceeded
	not daily_exceeded
}

decision := {
	"allow": false,
	"reason": "NIGHT_CAP_EXCEEDED",
	"reason_code": "CIP-POL-LIMIT",
	"details": {},
	"obligations": {},
} if {
	limit_ok
	night_exceeded
}

decision := {
	"allow": false,
	"reason": "BALANCE_DAILY_QUOTA_EXCEEDED",
	"reason_code": "CIP-POL-LIMIT",
	"details": {},
	"obligations": {},
} if {
	limit_ok
	not night_exceeded
	daily_exceeded
}
