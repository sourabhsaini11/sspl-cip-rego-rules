# BRIDGE-UPI ruleset v6 - UPI_PAY limits and the step-up gate (PDE architecture document,
# journey 1, rule UPI-R19).
#
# v5 behaviour is kept: the per-transaction, daily and night limits. New in v6: a payment from a
# device that is not verified, above the step-up threshold, is a STEP_UP with the obligation
# OTP_OR_APPROVED_FACTOR and the reason UPI_DEVICE_RISK. The enforcement point obtains the second
# factor and asks to re-evaluate; the PERMIT comes only from that second evaluation. A limit breach
# stays a DENY: a step-up never rescues a payment the limits refuse.
#
# Rules carry no data: limits and the threshold arrive in input.values. Input contract: v1.
# Fail closed: a missing or mistyped limit leaves `decision` undefined (RULE_UNDEFINED).
package cip.pde.bridge_upi.v6

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

# Every limit this ruleset reads must be present and a whole number. The check is positive on purpose:
# a rule that only excluded a malformed limit would let a missing one through (`not` of an undefined
# comparison is true), so no decision is ever produced without every limit.
limits_ok if {
	whole_number(input.values.per_txn_limit_inr)
	whole_number(input.values.daily_limit_inr)
	whole_number(input.values.night_cap_inr)
	whole_number(input.values.step_up_threshold_inr)
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

# An unverified device above the threshold. A verified device never steps up on this rule.
needs_step_up if {
	input.facts.device_verified == false
	input.facts.amount_inr > input.values.step_up_threshold_inr
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
	"result": "DENY",
	"reason": deny_reason,
	"reason_code": deny_code,
	"details": details,
} if {
	limits_ok
	deny_reason
}

decision := {
	"result": "STEP_UP",
	"reason": "UPI_DEVICE_RISK",
	"reason_code": "CIP-POL-TRUST",
	"obligation_refs": ["OTP_OR_APPROVED_FACTOR"],
	"details": details,
} if {
	limits_ok
	within_limits
	needs_step_up
}

decision := {
	"result": "PERMIT",
	"reason": "WITHIN_LIMITS",
	"details": details,
} if {
	limits_ok
	within_limits
	not needs_step_up
}
