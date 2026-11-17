# BRIDGE-AEPS ruleset v3 - Business Correspondent context and exposure (PDE architecture document,
# journey 6).
#
# v2 behaviour is kept: the daily ceiling with its step-up obligation. New in v3: the Business
# Correspondent must be authorised for the bank, the device certified, the terminal active and the
# shift permitted; otherwise the answer is a DENY (BC_NOT_AUTHORISED). A BC whose daily cash exposure
# would pass the locally approved limit (input.values.bc_daily_exposure_limit_inr, drawn so far in
# input.live.daily_drawn_inr) is a REFER with BC_EXPOSURE_LIMIT_EXCEEDED: only the bank may override
# it. A PERMIT means "the scheme flow may be initiated": it says nothing about settlement, and cash
# is never repeated blindly on an unknown outcome (the bank adapter reconciles).
#
# Operation: AEPS_WITHDRAWAL. Fail closed: a missing or mistyped limit leaves `decision` undefined.
# Input contract: v1.
package cip.pde.bridge_aeps.v3

whole_number(x) if {
	is_number(x)
	x == round(x)
}

# Every limit this ruleset reads must be present and a whole number. The check is positive on purpose:
# a rule that only excluded a malformed limit would let a missing one through (`not` of an undefined
# comparison is true), so no decision is ever produced without every limit.
limits_ok if {
	whole_number(input.values.daily_ceiling_inr)
	whole_number(input.values.step_up_threshold_inr)
	whole_number(input.values.bc_daily_exposure_limit_inr)
}

drawn := input.live.daily_drawn_inr

remaining := max([0, input.values.daily_ceiling_inr - drawn])

step_up := input.facts.amount_inr > input.values.step_up_threshold_inr

obligations := {"step_up_required": step_up}

bc_context_ok if {
	input.facts.bc_authorised
	input.facts.device_certified
	input.facts.terminal_active
	input.facts.shift_permitted
}

over_exposure if drawn + input.facts.amount_inr > input.values.bc_daily_exposure_limit_inr

decision := {
	"result": "DENY",
	"reason": "BC_NOT_AUTHORISED",
	"reason_code": "CIP-POL-TRUST",
	"details": {"live_counter_found": input.live.found},
} if {
	limits_ok
	not bc_context_ok
}

decision := {
	"result": "DENY",
	"reason": "INVALID_AMOUNT",
	"reason_code": "CIP-POL-DENY",
	"details": {"live_counter_found": input.live.found},
	"obligations": {"step_up_required": false},
} if {
	limits_ok
	bc_context_ok
	input.facts.amount_inr < 1
}

decision := {
	"result": "DENY",
	"reason": "DAILY_CEILING_EXCEEDED",
	"reason_code": "CIP-POL-LIMIT",
	"details": {"remaining_daily_allowance_inr": remaining, "live_counter_found": input.live.found},
	"obligations": obligations,
} if {
	limits_ok
	bc_context_ok
	input.facts.amount_inr >= 1
	input.facts.amount_inr > remaining
}

decision := {
	"result": "REFER",
	"reason": "BC_EXPOSURE_LIMIT_EXCEEDED",
	"reason_code": "CIP-POL-LIMIT",
	"obligation_refs": ["BANK_OVERRIDE_REQUIRED"],
	"details": {"live_counter_found": input.live.found},
	"obligations": obligations,
} if {
	limits_ok
	bc_context_ok
	input.facts.amount_inr >= 1
	input.facts.amount_inr <= remaining
	over_exposure
}

decision := {
	"result": "PERMIT",
	"reason": "WITHIN_CEILING",
	"details": {"remaining_daily_allowance_inr": remaining - input.facts.amount_inr, "live_counter_found": input.live.found},
	"obligations": obligations,
} if {
	limits_ok
	bc_context_ok
	input.facts.amount_inr >= 1
	input.facts.amount_inr <= remaining
	not over_exposure
}
