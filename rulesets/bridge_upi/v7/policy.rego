# BRIDGE-UPI ruleset v7 - UPI_PAY limits, the step-up gate and the L4 posture cap (PDE architecture
# document, section 3 acceptance scenario: a 12,000 payment under a GUARDED posture is denied with an
# effective limit of 8,000).
#
# v6 behaviour is kept. New in v7: under the GUARDED operating posture a payment may not exceed
# input.posture.limit_inr, the cap the L4 posture source reports with the posture (document section 3 and
# 7.3: L4 is a runtime input from its authority, never a bank value stored in the signed state). The posture only narrows (FF-14): the effective limit is the smaller of
# the bank's per-transaction limit and the cap, so a cap above the bank's limit changes nothing. A
# payment above the cap is a DENY UPI_GUARDED_LIMIT_EXCEEDED, and a step-up never rescues it. A verified
# completion of OTP_OR_APPROVED_FACTOR (ctx.completions) satisfies the device step-up; it never rescues a limit.
#
# The posture is read positively. NORMAL needs no cap. GUARDED needs a whole-number cap. Any other
# posture (RESTRICTED, which the PDS reports when the posture is missing or expired) leaves `decision`
# undefined, so the PDS records RULE_UNDEFINED: a missing posture never means wider limits.
#
# Rules carry no data: limits and the threshold arrive in input.values, the cap in input.posture. Input contract: v1.
# Fail closed: a missing or mistyped limit leaves `decision` undefined (RULE_UNDEFINED).
package cip.pde.bridge_upi.v7

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

posture_ok if input.posture.operating == "NORMAL"

posture_ok if {
	input.posture.operating == "GUARDED"
	whole_number(input.posture.limit_inr)
}

# Every limit this ruleset reads must be present and a whole number. The check is positive on purpose:
# a rule that only excluded a malformed limit would let a missing one through (`not` of an undefined
# comparison is true), so no decision is ever produced without every limit.
limits_ok if {
	whole_number(input.values.per_txn_limit_inr)
	whole_number(input.values.daily_limit_inr)
	whole_number(input.values.night_cap_inr)
	whole_number(input.values.step_up_threshold_inr)
	posture_ok
}

is_guarded if input.posture.operating == "GUARDED"

# The limit a payment is held to: the bank's, narrowed by the posture cap when GUARDED.
effective_limit_inr := min([input.values.per_txn_limit_inr, input.posture.limit_inr]) if is_guarded

effective_limit_inr := input.values.per_txn_limit_inr if input.posture.operating == "NORMAL"

over_guarded_cap if {
	is_guarded
	input.facts.amount_inr > input.posture.limit_inr
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
	input.facts.amount_inr <= effective_limit_inr
	input.live.daily_drawn_inr + input.facts.amount_inr <= input.values.daily_limit_inr
}

# The step-up is satisfied by a verified completion of OTP_OR_APPROVED_FACTOR. The PDS gives the rules only
# completions it has verified (MAC through the KMI, bound to this bank, provider, actor, purpose, request,
# facts, policy and effective state, not expired, used once), so a caller's flag can never stand in for one
# (document section 8). A missing or empty list means the obligation is still outstanding.
step_up_satisfied if {
	some c in input.ctx.completions
	c.obligation_ref == "OTP_OR_APPROVED_FACTOR"
}

# An unverified device above the threshold, with the second factor still outstanding. A verified device
# never steps up on this rule, and a completion never rescues a limit breach: it only lifts this step-up.
needs_step_up if {
	input.facts.device_verified == false
	input.facts.amount_inr > input.values.step_up_threshold_inr
	not step_up_satisfied
}

deny_reason := "INVALID_AMOUNT" if {
	invalid_amount
} else := "NIGHT_CAP_EXCEEDED" if {
	is_night
	input.facts.amount_inr > input.values.night_cap_inr
} else := "PER_TXN_LIMIT_EXCEEDED" if {
	input.facts.amount_inr > input.values.per_txn_limit_inr
} else := "UPI_GUARDED_LIMIT_EXCEEDED" if {
	over_guarded_cap
} else := "DAILY_LIMIT_EXCEEDED" if {
	input.live.daily_drawn_inr + input.facts.amount_inr > input.values.daily_limit_inr
}

deny_code := "CIP-POL-DENY" if {
	deny_reason == "INVALID_AMOUNT"
} else := "CIP-POL-LIMIT"

details := {"live_counter_found": input.live.found, "effective_limit_inr": effective_limit_inr, "requested_amount_inr": input.facts.amount_inr}

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
