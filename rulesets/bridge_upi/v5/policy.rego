# BRIDGE-UPI ruleset v5 - UPI_PAY limits.
#
# Rules carry no data: limits arrive in input.values (L1-L4 merged, from the signed
# effective state) and the day's draw in input.live. Input contract: v1
# (ctx, facts, values, posture, live, customer, contract).
#
# Fail closed: a decision is produced only on positive proof. If any limit is missing
# from input.values, or the clock cannot be read, `decision` is undefined and the PDE
# records a REJECT with reason RULE_UNDEFINED. Absence never means allow.
#
# Live counter: input.live.found == false means no counter exists (nothing drawn yet,
# or the counter was lost - the counter's writer is an open dependency, DEP-02). This
# ruleset treats a missing counter as nothing drawn and always reports
# details.live_counter_found so the record shows which case applied.
#
# Typed limits: a limit that is present but not a whole number (a string, a list, a
# fraction) is a malformed state document. In Rego a number sorts before a string, so
# `amount <= "100000"` is true; without this guard such a value would allow everything.
# A malformed limit leaves `decision` undefined, like a missing one.
#
# Night is judged on the PDE clock in the PDE zone (input.ctx.tz), not UTC and not the
# caller's clock. night_start_hour and night_end_hour are the only policy constants in
# this file.
package cip.pde.bridge_upi.v5

night_start_hour := 22

night_end_hour := 6

local_hour := time.clock([time.parse_rfc3339_ns(input.ctx.now), input.ctx.tz])[0]

is_night if local_hour >= night_start_hour

is_night if local_hour < night_end_hour

is_day if {
	local_hour >= night_end_hour
	local_hour < night_start_hour
}

whole_number(x) if {
	is_number(x)
	x == round(x)
}

malformed_limit if {
	some name in {"per_txn_limit_inr", "daily_limit_inr", "night_cap_inr"}
	not whole_number(input.values[name])
	input.values[name]
}

invalid_amount if input.facts.amount_inr < 1

night_ok if is_day

night_ok if {
	is_night
	input.facts.amount_inr <= input.values.night_cap_inr
}

within_limits if {
	not invalid_amount
	night_ok
	input.facts.amount_inr <= input.values.per_txn_limit_inr
	input.live.daily_drawn_inr + input.facts.amount_inr <= input.values.daily_limit_inr
}

deny_reason := "INVALID_AMOUNT" if {
	invalid_amount
} else := "NIGHT_CAP_EXCEEDED" if {
	is_night
	input.facts.amount_inr > input.values.night_cap_inr
} else := "PER_TXN_LIMIT_EXCEEDED" if {
	input.facts.amount_inr > input.values.per_txn_limit_inr
} else := "DAILY_LIMIT_EXCEEDED" if {
	input.live.daily_drawn_inr + input.facts.amount_inr > input.values.daily_limit_inr
}

deny_code := "CIP-POL-DENY" if {
	deny_reason == "INVALID_AMOUNT"
} else := "CIP-POL-LIMIT"

details := {"live_counter_found": input.live.found}

decision := {
	"allow": false,
	"reason": deny_reason,
	"reason_code": deny_code,
	"details": details,
} if {
	not malformed_limit
	deny_reason
}

decision := {
	"allow": true,
	"reason": "WITHIN_LIMITS",
	"details": details,
} if {
	not malformed_limit
	within_limits
}
